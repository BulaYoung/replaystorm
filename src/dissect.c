#include "dissect.h"

#include <string.h>

static inline uint16_t be16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static inline int is_vlan_tpid(uint16_t t)
{
	return t == ETHT_VLAN || t == ETHT_QINQ || t == ETHT_QINQ_OLD1 || t == ETHT_QINQ_OLD2;
}

static inline int has_ports(uint8_t proto)
{
	/* TCP, UDP, DCCP, SCTP, UDP-Lite */
	return proto == 6 || proto == 17 || proto == 33 || proto == 132 || proto == 136;
}

static void parse_l4(const uint8_t *p, uint32_t len, dis_t *d, uint32_t l4)
{
	if (l4 > 0xFFFF)
		return;
	d->l4_off = (uint16_t)l4;
	if (!d->frag && has_ports(d->proto) && l4 + 4 <= len) {
		d->sport = be16(p + l4);
		d->dport = be16(p + l4 + 2);
	}
}

static void parse_ipv4(const uint8_t *p, uint32_t len, uint32_t off, dis_t *d)
{
	if (off + 20 > len || (p[off] >> 4) != 4)
		return;
	uint32_t ihl = (uint32_t)(p[off] & 0x0F) * 4;
	if (ihl < 20 || off + ihl > len)
		return;
	d->l3 = 4;
	d->l3_off = (uint16_t)off;
	d->proto = p[off + 9];
	d->src = p + off + 12;
	d->dst = p + off + 16;
	uint16_t fo = be16(p + off + 6);
	uint16_t frag_off = fo & 0x1FFF;
	d->frag = (fo & 0x2000) || frag_off != 0;
	d->frag_first = (frag_off == 0);
	if (d->frag_first)
		parse_l4(p, len, d, off + ihl);
}

static void parse_ipv6(const uint8_t *p, uint32_t len, uint32_t off, dis_t *d)
{
	if (off + 40 > len || (p[off] >> 4) != 6)
		return;
	d->l3 = 6;
	d->l3_off = (uint16_t)off;
	d->src = p + off + 8;
	d->dst = p + off + 24;
	d->frag_first = 1;
	uint8_t nh = p[off + 6];
	uint32_t cur = off + 40;
	for (int i = 0; i < 8; i++) {
		if (nh == 0 || nh == 43 || nh == 60 || nh == 135) {
			if (cur + 8 > len) {
				d->proto = nh;
				return;
			}
			uint8_t next = p[cur];
			cur += ((uint32_t)p[cur + 1] + 1) * 8;
			nh = next;
		} else if (nh == 51) { /* AH */
			if (cur + 8 > len) {
				d->proto = nh;
				return;
			}
			uint8_t next = p[cur];
			cur += ((uint32_t)p[cur + 1] + 2) * 4;
			nh = next;
		} else if (nh == 44) { /* фрагмент */
			if (cur + 8 > len) {
				d->proto = nh;
				d->frag = 1;
				d->frag_first = 0;
				return;
			}
			uint16_t fo = be16(p + cur + 2);
			d->frag = 1;
			d->frag_first = ((fo & 0xFFF8) == 0);
			nh = p[cur];
			cur += 8;
		} else {
			break;
		}
	}
	d->proto = nh;
	if (d->frag_first && cur <= len)
		parse_l4(p, len, d, cur);
}

static void parse_ip_by_version(const uint8_t *p, uint32_t len, uint32_t off, dis_t *d)
{
	if (off >= len)
		return;
	uint8_t v = p[off] >> 4;
	if (v == 4)
		parse_ipv4(p, len, off, d);
	else if (v == 6)
		parse_ipv6(p, len, off, d);
}

static void parse_eth(const uint8_t *p, uint32_t len, uint32_t off, dis_t *d, int depth);

static void parse_ethertype(const uint8_t *p, uint32_t len, uint32_t off, uint16_t et, dis_t *d,
                            int depth)
{
	/* VLAN / QinQ */
	for (int i = 0; i < 8 && is_vlan_tpid(et); i++) {
		if (off + 4 > len)
			return;
		d->vlan_depth++;
		et = be16(p + off + 2);
		off += 4;
	}
	switch (et) {
	case ETHT_IPV4: parse_ipv4(p, len, off, d); return;
	case ETHT_IPV6: parse_ipv6(p, len, off, d); return;
	case ETHT_ARP: d->l2kind = L2K_ARP; return;
	case ETHT_LLDP: d->l2kind = L2K_LLDP; return;
	case ETHT_MPLS_UC:
	case ETHT_MPLS_MC:
		d->mpls = 1;
		for (int i = 0; i < 16; i++) {
			if (off + 4 > len)
				return;
			int bos = p[off + 2] & 1;
			off += 4;
			if (bos)
				break;
		}
		if (off >= len)
			return;
		switch (p[off] >> 4) {
		case 4: parse_ipv4(p, len, off, d); return;
		case 6: parse_ipv6(p, len, off, d); return;
		case 0:
			/* Псевдопровод с control word: внутри Ethernet-кадр. */
			if (depth == 0)
				parse_eth(p, len, off + 4, d, depth + 1);
			return;
		default: return;
		}
	case ETHT_PPPOE_S:
		if (off + 8 > len)
			return;
		{
			uint16_t ppp = be16(p + off + 6);
			d->pppoe = 1;
			if (ppp == 0x0021)
				parse_ipv4(p, len, off + 8, d);
			else if (ppp == 0x0057)
				parse_ipv6(p, len, off + 8, d);
		}
		return;
	default:
		if (et < 0x0600)
			d->l2kind = L2K_LLC;
		return;
	}
}

static void parse_eth(const uint8_t *p, uint32_t len, uint32_t off, dis_t *d, int depth)
{
	if (off + ETH_HLEN_ > len)
		return;
	uint16_t et = be16(p + off + 12);
	if (depth == 0)
		d->outer_ethertype = et;
	parse_ethertype(p, len, off + ETH_HLEN_, et, d, depth);
}

void afr_dissect(const uint8_t *p, uint32_t len, int raw_ip, dis_t *d)
{
	memset(d, 0, sizeof(*d));
	d->l2kind = L2K_OTHER;
	switch (raw_ip) {
	case 0: parse_eth(p, len, 0, d, 0); break;
	case 4: parse_ipv4(p, len, 0, d); break;
	case 6: parse_ipv6(p, len, 0, d); break;
	default: parse_ip_by_version(p, len, 0, d); break;
	}
	if (d->l3)
		d->l2kind = L2K_IP;
}

static inline uint64_t mix64(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 33;
	return x;
}

static inline uint64_t ld64(const uint8_t *p)
{
	uint64_t v;
	memcpy(&v, p, 8);
	return v;
}

uint64_t afr_flow_hash(const dis_t *d)
{
	uint16_t pa = d->sport, pb = d->dport;
	uint64_t h;
	if (d->l3 == 4) {
		uint32_t a, b;
		memcpy(&a, d->src, 4);
		memcpy(&b, d->dst, 4);
		/* Упорядочиваем концы соединения, чтобы хеш был симметричным. */
		if (a > b || (a == b && pa > pb)) {
			uint32_t t = a;
			a = b;
			b = t;
			uint16_t tp = pa;
			pa = pb;
			pb = tp;
		}
		h = mix64(((uint64_t)a << 32) | b);
	} else {
		const uint8_t *a = d->src, *b = d->dst;
		int c = memcmp(a, b, 16);
		if (c > 0 || (c == 0 && pa > pb)) {
			const uint8_t *t = a;
			a = b;
			b = t;
			uint16_t tp = pa;
			pa = pb;
			pb = tp;
		}
		h = mix64(ld64(a) ^ 0x9e3779b97f4a7c15ULL);
		h = mix64(h ^ ld64(a + 8));
		h = mix64(h ^ ld64(b));
		h = mix64(h ^ ld64(b + 8));
	}
	return mix64(h ^ (((uint64_t)pa << 32) | ((uint64_t)pb << 16) | d->proto));
}
