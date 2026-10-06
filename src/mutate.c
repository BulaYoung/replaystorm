#include "mutate.h"

#include "dissect.h"

static inline uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static inline void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)rd16(p) << 16) | rd16(p + 2);
}

static inline void wr32(uint8_t *p, uint32_t v)
{
	wr16(p, (uint16_t)(v >> 16));
	wr16(p + 2, (uint16_t)v);
}

/* Account for replacing 32-bit word old -> new in the checksum at csum. */
static inline void csum_fix32(uint8_t *csum, uint32_t old, uint32_t new_)
{
	uint16_t c = rd16(csum);
	c = afr_csum_update16(c, (uint16_t)(old >> 16), (uint16_t)(new_ >> 16));
	c = afr_csum_update16(c, (uint16_t)old, (uint16_t)new_);
	wr16(csum, c);
}

static inline uint16_t shift_port(uint16_t p, uint64_t lap, uint32_t step)
{
	/* Ports < 1024 (services) are left alone; others are shifted within 1024..65535. */
	if (p < 1024)
		return p;
	uint64_t r = ((uint64_t)(p - 1024) + lap * step) % 64512u;
	return (uint16_t)(1024 + r);
}

/* Location of the L4 checksum covering the pseudo-header (NULL if none). */
static uint8_t *l4_csum(uint8_t *f, uint32_t len, const dis_t *d, int *is_udp)
{
	*is_udp = 0;
	if (!d->l4_off || !d->frag_first)
		return NULL;
	uint32_t off;
	switch (d->proto) {
	case 6: off = 16; break;
	case 17:
		off = 6;
		*is_udp = 1;
		break;
	case 58:
		if (d->l3 != 6)
			return NULL;
		off = 2;
		break;
	default: return NULL;
	}
	if ((uint32_t)d->l4_off + off + 2 > len)
		return NULL;
	uint8_t *c = f + d->l4_off + off;
	/* UDP over IPv4 with a zero checksum: the checksum is not used. */
	if (*is_udp && rd16(c) == 0)
		return NULL;
	return c;
}

int afr_mutate(uint8_t *f, uint32_t len, uint64_t lap, const mutate_cfg_t *cfg)
{
	if (lap == 0)
		return 0;
	dis_t d;
	afr_dissect(f, len, cfg->raw_ip, &d);
	if (!d.l3)
		return 0;
	int is_udp;
	uint8_t *l4c = l4_csum(f, len, &d, &is_udp);
	int changed = 0;

	if (cfg->ip) {
		const uint32_t delta = (uint32_t)(lap * cfg->ip_offset);
		if (d.l3 == 4) {
			uint8_t *ip = f + d.l3_off;
			for (int k = 0; k < 2; k++) {
				uint8_t *a = ip + 12 + 4 * k;
				uint32_t old = rd32(a), nw = old + delta;
				wr32(a, nw);
				csum_fix32(ip + 10, old, nw);
				if (l4c)
					csum_fix32(l4c, old, nw);
			}
		} else {
			/* IPv6: shift address bytes 8..11 (upper part of the interface identifier). */
			uint8_t *ip = f + d.l3_off;
			for (int k = 0; k < 2; k++) {
				uint8_t *a = ip + 8 + 16 * k + 8;
				uint32_t old = rd32(a), nw = old + delta;
				wr32(a, nw);
				if (l4c)
					csum_fix32(l4c, old, nw);
			}
		}
		changed = 1;
	}

	if (cfg->port && !d.frag && (d.proto == 6 || d.proto == 17) && d.l4_off &&
	    (uint32_t)d.l4_off + 4 <= len) {
		uint8_t *pp = f + d.l4_off;
		uint32_t old = rd32(pp);
		uint16_t s = shift_port(rd16(pp), lap, cfg->port_step);
		uint16_t t = shift_port(rd16(pp + 2), lap, cfg->port_step);
		uint32_t nw = ((uint32_t)s << 16) | t;
		if (nw != old) {
			wr32(pp, nw);
			if (l4c)
				csum_fix32(l4c, old, nw);
			changed = 1;
		}
	}
	/* In UDP zero means "no checksum"; a computed zero is sent as 0xFFFF. */
	if (l4c && is_udp && rd16(l4c) == 0)
		wr16(l4c, 0xFFFF);
	return changed;
}
