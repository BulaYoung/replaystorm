#include "dissect.h"
#include "index.h"
#include "t.h"

#include <string.h>

/* Сборщик кадров для тестов. */
typedef struct {
	uint8_t b[256];
	size_t n;
} fr_t;

static void p8(fr_t *f, uint8_t v) { f->b[f->n++] = v; }
static void p16(fr_t *f, uint16_t v) { p8(f, (uint8_t)(v >> 8)); p8(f, (uint8_t)v); }
static void p32(fr_t *f, uint32_t v) { p16(f, (uint16_t)(v >> 16)); p16(f, (uint16_t)v); }
static void pn(fr_t *f, const uint8_t *p, size_t n) { memcpy(f->b + f->n, p, n); f->n += n; }

static void eth(fr_t *f, uint16_t et)
{
	static const uint8_t m[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	f->n = 0;
	pn(f, m, 12);
	p16(f, et);
}

static void ip4(fr_t *f, uint32_t s, uint32_t d, uint8_t proto, uint16_t fragoff)
{
	p8(f, 0x45); p8(f, 0); p16(f, 40); p16(f, 1); p16(f, fragoff); p8(f, 64); p8(f, proto); p16(f, 0);
	p32(f, s); p32(f, d);
}

static void ports(fr_t *f, uint16_t s, uint16_t d)
{
	p16(f, s); p16(f, d); p32(f, 0); p32(f, 0); p32(f, 0); p32(f, 0);
}

static void ip6(fr_t *f, uint8_t s, uint8_t d, uint8_t nh)
{
	uint8_t a[16] = {0x20, 0x01, 0x0d, 0xb8};
	p32(f, 0x60000000); p16(f, 20); p8(f, nh); p8(f, 64);
	a[15] = s; pn(f, a, 16);
	a[15] = d; pn(f, a, 16);
}

typedef void (*build_fn)(fr_t *f, int rev);

static void b_v4(fr_t *f, int rev)
{
	eth(f, 0x0800);
	ip4(f, rev ? 0x0a000002 : 0x0a000001, rev ? 0x0a000001 : 0x0a000002, 6, 0);
	ports(f, rev ? 443 : 51000, rev ? 51000 : 443);
}

static void b_vlan(fr_t *f, int rev)
{
	/* VLAN ID разный в двух направлениях — в хеш он не входит */
	eth(f, 0x8100);
	p16(f, rev ? 20 : 10); p16(f, 0x0800);
	ip4(f, rev ? 0xc0a80002 : 0xc0a80001, rev ? 0xc0a80001 : 0xc0a80002, 17, 0);
	ports(f, rev ? 53 : 3333, rev ? 3333 : 53);
}

static void b_qinq(fr_t *f, int rev)
{
	eth(f, 0x88a8);
	p16(f, 100); p16(f, 0x8100); p16(f, 200); p16(f, 0x0800);
	ip4(f, rev ? 0x01020304 : 0x05060708, rev ? 0x05060708 : 0x01020304, 6, 0);
	ports(f, rev ? 80 : 1234, rev ? 1234 : 80);
}

static void b_mpls(fr_t *f, int rev)
{
	eth(f, 0x8847);
	p32(f, (16u << 12) | 64); p32(f, (17u << 12) | (1u << 8) | 64);
	ip4(f, rev ? 0x0b000002 : 0x0b000001, rev ? 0x0b000001 : 0x0b000002, 17, 0);
	ports(f, rev ? 9 : 10, rev ? 10 : 9);
}

static void b_v6(fr_t *f, int rev)
{
	eth(f, 0x86dd);
	ip6(f, rev ? 2 : 1, rev ? 1 : 2, 6);
	ports(f, rev ? 80 : 50000, rev ? 50000 : 80);
}

static void b_v6ext(fr_t *f, int rev)
{
	eth(f, 0x86dd);
	ip6(f, rev ? 2 : 1, rev ? 1 : 2, 0);
	p8(f, 17); p8(f, 0); p16(f, 0); p32(f, 0); /* hop-by-hop, 8 байт */
	ports(f, rev ? 53 : 4000, rev ? 4000 : 53);
}

static void b_pppoe(fr_t *f, int rev)
{
	eth(f, 0x8864);
	p8(f, 0x11); p8(f, 0); p16(f, 1); p16(f, 42); p16(f, 0x0021);
	ip4(f, rev ? 0x08080808 : 0x64400001, rev ? 0x64400001 : 0x08080808, 17, 0);
	ports(f, rev ? 53 : 33333, rev ? 33333 : 53);
}

static void sym_case(build_fn fn, const char *name, uint8_t l3, int ports_expected)
{
	fr_t a, b;
	fn(&a, 0);
	fn(&b, 1);
	dis_t da, db;
	afr_dissect(a.b, (uint32_t)a.n, 0, &da);
	afr_dissect(b.b, (uint32_t)b.n, 0, &db);
	CHECK_EQ(da.l3, l3);
	CHECK_EQ(db.l3, l3);
	if (ports_expected)
		CHECK(da.sport != 0 && da.dport != 0);
	uint64_t ha = afr_flow_hash(&da), hb = afr_flow_hash(&db);
	if (ha != hb)
		fprintf(stderr, "  несимметричный хеш: %s\n", name);
	CHECK(ha == hb);
	idx_cfg_t cfg = {.ip_shards = 7, .max_frame = 1514};
	int r1 = 0, r2 = 0;
	CHECK_EQ(afr_classify(a.b, (uint32_t)a.n, 0, &cfg, &da, &r1),
	         afr_classify(b.b, (uint32_t)b.n, 0, &cfg, &db, &r2));
}

static void fragments(void)
{
	/* Фрагменты одной датаграммы: порты не учитываются, шард один. */
	fr_t f1, f2, f3;
	eth(&f1, 0x0800);
	ip4(&f1, 0x0a000001, 0x0a000002, 17, 0x2000); /* MF, offset 0 */
	ports(&f1, 1111, 2222);
	eth(&f2, 0x0800);
	ip4(&f2, 0x0a000001, 0x0a000002, 17, 0x2000 | 125);
	p32(&f2, 0xdeadbeef); p32(&f2, 0x12345678);
	eth(&f3, 0x0800);
	ip4(&f3, 0x0a000002, 0x0a000001, 17, 250); /* последний фрагмент, обратное направление */
	p32(&f3, 0xcafebabe); p32(&f3, 0);
	dis_t d1, d2, d3;
	afr_dissect(f1.b, (uint32_t)f1.n, 0, &d1);
	afr_dissect(f2.b, (uint32_t)f2.n, 0, &d2);
	afr_dissect(f3.b, (uint32_t)f3.n, 0, &d3);
	CHECK(d1.frag && d2.frag && d3.frag);
	CHECK(d1.frag_first && !d2.frag_first && !d3.frag_first);
	CHECK_EQ(d1.sport, 0);
	CHECK_EQ(d1.l4_off, 34); /* у первого фрагмента L4 есть (для контрольных сумм) */
	CHECK_EQ(d2.l4_off, 0);
	CHECK(afr_flow_hash(&d1) == afr_flow_hash(&d2));
	CHECK(afr_flow_hash(&d1) == afr_flow_hash(&d3));

	/* IPv6-фрагменты */
	fr_t g1, g2;
	eth(&g1, 0x86dd);
	ip6(&g1, 1, 2, 44);
	p8(&g1, 17); p8(&g1, 0); p16(&g1, 1); p32(&g1, 7); /* offset 0, M */
	ports(&g1, 5, 6);
	eth(&g2, 0x86dd);
	ip6(&g2, 2, 1, 44);
	p8(&g2, 17); p8(&g2, 0); p16(&g2, (100 << 3)); p32(&g2, 7);
	p32(&g2, 0);
	dis_t e1, e2;
	afr_dissect(g1.b, (uint32_t)g1.n, 0, &e1);
	afr_dissect(g2.b, (uint32_t)g2.n, 0, &e2);
	CHECK(e1.frag && e2.frag);
	CHECK_EQ(e1.proto, 17);
	CHECK_EQ(e2.proto, 17);
	CHECK(afr_flow_hash(&e1) == afr_flow_hash(&e2));
}

static void non_ip(void)
{
	idx_cfg_t cfg = {.ip_shards = 5, .max_frame = 1514};
	fr_t f;
	dis_t d;
	int r = 0;
	eth(&f, 0x0806);
	for (int i = 0; i < 28; i++)
		p8(&f, 0);
	CHECK_EQ(afr_classify(f.b, (uint32_t)f.n, 0, &cfg, &d, &r), 5);
	CHECK_EQ(d.l2kind, L2K_ARP);
	/* STP: 802.3 + LLC */
	eth(&f, 38);
	p8(&f, 0x42); p8(&f, 0x42); p8(&f, 3);
	for (int i = 0; i < 35; i++)
		p8(&f, 0);
	CHECK_EQ(afr_classify(f.b, (uint32_t)f.n, 0, &cfg, &d, &r), 5);
	CHECK_EQ(d.l2kind, L2K_LLC);
	/* LLDP в VLAN */
	eth(&f, 0x8100);
	p16(&f, 5); p16(&f, 0x88cc);
	for (int i = 0; i < 30; i++)
		p8(&f, 0);
	CHECK_EQ(afr_classify(f.b, (uint32_t)f.n, 0, &cfg, &d, &r), 5);
	CHECK_EQ(d.l2kind, L2K_LLDP);
	CHECK_EQ(d.vlan_depth, 1);
}

static void raw_ip(void)
{
	fr_t f;
	f.n = 0;
	ip4(&f, 1, 2, 6, 0);
	ports(&f, 10, 20);
	dis_t d;
	afr_dissect(f.b, (uint32_t)f.n, 1, &d);
	CHECK_EQ(d.l3, 4);
	CHECK_EQ(d.sport, 10);
	f.n = 0;
	ip6(&f, 1, 2, 17);
	ports(&f, 10, 20);
	afr_dissect(f.b, (uint32_t)f.n, 1, &d);
	CHECK_EQ(d.l3, 6);
	CHECK_EQ(d.dport, 20);
	idx_cfg_t cfg = {.ip_shards = 3, .max_frame = 1514};
	int r = -1;
	f.b[0] = 0x50; /* не IP */
	CHECK_EQ(afr_classify(f.b, (uint32_t)f.n, 1, &cfg, &d, &r), SHARD_SKIP);
	CHECK_EQ(r, SKIP_BAD_RAW);
}

static void distribution(void)
{
	/* Разные потоки расходятся по шардам примерно равномерно. */
	idx_cfg_t cfg = {.ip_shards = 8, .max_frame = 1514};
	unsigned cnt[9] = {0};
	for (unsigned i = 0; i < 8000; i++) {
		fr_t f;
		eth(&f, 0x0800);
		ip4(&f, 0x0a000000 + i, 0xc0a80001, 6, 0);
		ports(&f, (uint16_t)(1024 + i), 443);
		dis_t d;
		int r;
		cnt[afr_classify(f.b, (uint32_t)f.n, 0, &cfg, &d, &r)]++;
	}
	for (int s = 0; s < 8; s++)
		CHECK(cnt[s] > 800 && cnt[s] < 1200);
	CHECK_EQ(cnt[8], 0);
}

static void mtu_limits(void)
{
	idx_cfg_t cfg = {.ip_shards = 2, .max_frame = 1514};
	uint8_t big[1600] = {0};
	big[12] = 0x08;
	big[14] = 0x45;
	dis_t d;
	int r;
	CHECK(afr_classify(big, 1514, 0, &cfg, &d, &r) != SHARD_SKIP);
	CHECK(afr_classify(big, 1515, 0, &cfg, &d, &r) == SHARD_SKIP);
	big[12] = 0x81; /* 802.1Q даёт ещё 4 байта */
	big[13] = 0x00;
	big[16] = 0x08;
	big[17] = 0x00;
	big[18] = 0x45;
	CHECK(afr_classify(big, 1518, 0, &cfg, &d, &r) != SHARD_SKIP);
	CHECK(afr_classify(big, 1519, 0, &cfg, &d, &r) == SHARD_SKIP);
	big[12] = 0x88; /* 802.1ad — ядро не делает для него исключения */
	big[13] = 0xa8;
	CHECK(afr_classify(big, 1518, 0, &cfg, &d, &r) == SHARD_SKIP);
}

void test_hash(void)
{
	sym_case(b_v4, "IPv4", 4, 1);
	sym_case(b_vlan, "VLAN", 4, 1);
	sym_case(b_qinq, "QinQ", 4, 1);
	sym_case(b_mpls, "MPLS", 4, 1);
	sym_case(b_v6, "IPv6", 6, 1);
	sym_case(b_v6ext, "IPv6 ext", 6, 1);
	sym_case(b_pppoe, "PPPoE", 4, 1);
	fragments();
	non_ip();
	raw_ip();
	distribution();
	mtu_limits();
}
