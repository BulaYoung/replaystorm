#include "dissect.h"
#include "mutate.h"
#include "t.h"

#include <string.h>

/* Полный пересчёт контрольной суммы для проверки инкрементального. */
static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s)
{
	for (size_t i = 0; i + 1 < n; i += 2)
		s += (uint32_t)((p[i] << 8) | p[i + 1]);
	if (n & 1)
		s += (uint32_t)(p[n - 1] << 8);
	return s;
}

static uint16_t fold(uint32_t s)
{
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return (uint16_t)~s;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* Проверить, что IP- и L4-суммы кадра корректны (как при полном пересчёте). */
static int sums_ok(const uint8_t *f, uint32_t len)
{
	dis_t d;
	afr_dissect(f, len, 0, &d);
	if (d.l3 == 4) {
		const uint8_t *ip = f + d.l3_off;
		if (fold(sum16(ip, (size_t)(ip[0] & 0xF) * 4, 0)) != 0)
			return 0;
	}
	if (!d.l4_off || !d.frag_first)
		return 1;
	uint32_t seglen = len - d.l4_off;
	uint32_t ps = 0;
	if (d.l3 == 4) {
		ps = sum16(f + d.l3_off + 12, 8, 0) + d.proto + seglen;
	} else {
		ps = sum16(f + d.l3_off + 8, 32, 0) + d.proto + seglen;
	}
	if (d.proto == 17 && rd16(f + d.l4_off + 6) == 0)
		return 1;
	return fold(sum16(f + d.l4_off, seglen, ps)) == 0;
}

/* Заполнить корректные суммы. */
static void fill_sums(uint8_t *f, uint32_t len)
{
	dis_t d;
	afr_dissect(f, len, 0, &d);
	if (d.l3 == 4) {
		uint8_t *ip = f + d.l3_off;
		wr16(ip + 10, 0);
		wr16(ip + 10, fold(sum16(ip, (size_t)(ip[0] & 0xF) * 4, 0)));
	}
	if (!d.l4_off || !d.frag_first)
		return;
	uint32_t off = d.proto == 6 ? 16 : d.proto == 17 ? 6 : 2;
	uint32_t seglen = len - d.l4_off;
	wr16(f + d.l4_off + off, 0);
	uint32_t ps = d.l3 == 4 ? sum16(f + d.l3_off + 12, 8, 0) : sum16(f + d.l3_off + 8, 32, 0);
	ps += d.proto + seglen;
	uint16_t c = fold(sum16(f + d.l4_off, seglen, ps));
	if (d.proto == 17 && c == 0)
		c = 0xFFFF;
	wr16(f + d.l4_off + off, c);
}

static uint32_t build_v4(uint8_t *f, int vlan, uint8_t proto, uint32_t s, uint32_t dd,
                         uint16_t sp, uint16_t dp, uint16_t frag)
{
	uint32_t o = 0;
	for (int i = 0; i < 12; i++)
		f[o++] = (uint8_t)(0xa0 + i);
	if (vlan) {
		wr16(f + o, 0x8100);
		wr16(f + o + 2, 42);
		o += 4;
	}
	wr16(f + o, 0x0800);
	o += 2;
	uint32_t l3 = o;
	uint32_t payload = 37;
	uint32_t l4len = (proto == 6 ? 20 : 8) + payload;
	memset(f + o, 0, 20);
	f[o] = 0x45;
	wr16(f + o + 2, (uint16_t)(20 + l4len));
	wr16(f + o + 6, frag);
	f[o + 8] = 64;
	f[o + 9] = proto;
	f[o + 12] = (uint8_t)(s >> 24); f[o + 13] = (uint8_t)(s >> 16); f[o + 14] = (uint8_t)(s >> 8); f[o + 15] = (uint8_t)s;
	f[o + 16] = (uint8_t)(dd >> 24); f[o + 17] = (uint8_t)(dd >> 16); f[o + 18] = (uint8_t)(dd >> 8); f[o + 19] = (uint8_t)dd;
	o = l3 + 20;
	memset(f + o, 0, l4len);
	wr16(f + o, sp);
	wr16(f + o + 2, dp);
	if (proto == 6)
		f[o + 12] = 0x50;
	else
		wr16(f + o + 4, (uint16_t)l4len);
	for (uint32_t i = 0; i < payload; i++)
		f[o + l4len - payload + i] = (uint8_t)(i * 7 + 3);
	o += l4len;
	fill_sums(f, o);
	return o;
}

static uint32_t build_v6(uint8_t *f, uint8_t proto)
{
	uint32_t o = 0;
	for (int i = 0; i < 12; i++)
		f[o++] = (uint8_t)(0xb0 + i);
	wr16(f + o, 0x86dd);
	o += 2;
	uint32_t l4len = (proto == 6 ? 20 : 8) + 25;
	memset(f + o, 0, 40);
	f[o] = 0x60;
	wr16(f + o + 4, (uint16_t)l4len);
	f[o + 6] = proto;
	f[o + 7] = 64;
	for (int i = 0; i < 16; i++) {
		f[o + 8 + i] = (uint8_t)(0x20 + i);
		f[o + 24 + i] = (uint8_t)(0x90 + i);
	}
	o += 40;
	memset(f + o, 0, l4len);
	wr16(f + o, 50000);
	wr16(f + o + 2, 443);
	if (proto == 6)
		f[o + 12] = 0x50;
	else
		wr16(f + o + 4, (uint16_t)l4len);
	for (int i = 0; i < 25; i++)
		f[o + l4len - 25 + i] = (uint8_t)(i * 13);
	o += l4len;
	fill_sums(f, o);
	return o;
}

static void v4_cases(void)
{
	mutate_cfg_t cfg = {.ip = 1, .port = 1, .ip_offset = 0x00010000u, .port_step = 1};
	for (int vlan = 0; vlan < 2; vlan++) {
		for (int pi = 0; pi < 2; pi++) {
			uint8_t proto = pi ? 17 : 6;
			uint8_t f[256], orig[256];
			uint32_t len = build_v4(f, vlan, proto, 0x0a000001, 0xc0a80105, 51000, 443, 0);
			memcpy(orig, f, len);
			CHECK(sums_ok(f, len));
			CHECK_EQ(afr_mutate(f, len, 0, &cfg), 0); /* круг 0 не меняется */
			CHECK(memcmp(f, orig, len) == 0);
			CHECK_EQ(afr_mutate(f, len, 3, &cfg), 1);
			CHECK(sums_ok(f, len));
			uint32_t l2 = vlan ? 18 : 14;
			CHECK(memcmp(f, orig, l2) == 0); /* L2 не тронут */
			const uint8_t *ip = f + l2;
			CHECK_EQ(ip[13], 0x03); /* 10.0.0.1 + 3*0.1.0.0 = 10.3.0.1 */
			CHECK_EQ(ip[17], 0xab); /* 192.168.1.5 -> 192.171.1.5 */
			CHECK_EQ(rd16(ip + 20), 51003);
			CHECK_EQ(rd16(ip + 22), 443); /* порт < 1024 не меняется */
		}
	}
	/* UDP без контрольной суммы: остаётся без неё */
	uint8_t f[256];
	uint32_t len = build_v4(f, 0, 17, 1, 2, 2000, 3000, 0);
	wr16(f + 14 + 20 + 6, 0);
	afr_mutate(f, len, 1, &cfg);
	CHECK_EQ(rd16(f + 14 + 20 + 6), 0);
	CHECK(sums_ok(f, len));
	/* Перенос через 65535 у порта и через 255 у октета */
	len = build_v4(f, 0, 6, 0x0affffff, 0x0b000000, 65535, 65000, 0);
	afr_mutate(f, len, 1, &cfg);
	CHECK(sums_ok(f, len));
	CHECK_EQ(rd16(f + 34), 1024);
	/* Симметрия: прямой и обратный пакет после сдвига по-прежнему зеркальны */
	uint8_t a[256], b[256];
	uint32_t la = build_v4(a, 0, 6, 0x0a000001, 0x0a000002, 40000, 50000, 0);
	uint32_t lb = build_v4(b, 0, 6, 0x0a000002, 0x0a000001, 50000, 40000, 0);
	afr_mutate(a, la, 5, &cfg);
	afr_mutate(b, lb, 5, &cfg);
	CHECK(memcmp(a + 26, b + 30, 4) == 0 && memcmp(a + 30, b + 26, 4) == 0);
	CHECK(rd16(a + 34) == rd16(b + 36) && rd16(a + 36) == rd16(b + 34));
	dis_t da, db;
	afr_dissect(a, la, 0, &da);
	afr_dissect(b, lb, 0, &db);
	CHECK(afr_flow_hash(&da) == afr_flow_hash(&db));
}

static void fragments(void)
{
	mutate_cfg_t cfg = {.ip = 1, .port = 1, .ip_offset = 0x00010000u, .port_step = 1};
	uint8_t f[256];
	/* Первый фрагмент: L4-сумма покрывает всю датаграмму, сдвигаем только адреса
	 * (порты у фрагментов не трогаем, иначе разойдутся с остальными фрагментами). */
	uint32_t len = build_v4(f, 0, 17, 0x0a000001, 0x0a000002, 5000, 6000, 0x2000);
	uint16_t c0 = rd16(f + 34 + 6);
	afr_mutate(f, len, 2, &cfg);
	CHECK_EQ(rd16(f + 34), 5000);
	CHECK(rd16(f + 34 + 6) != c0);
	CHECK_EQ(fold(sum16(f + 14, 20, 0)), 0);
	/* Не первый фрагмент: L4 нет, меняются только адреса и сумма IP */
	len = build_v4(f, 0, 17, 0x0a000001, 0x0a000002, 0x1111, 0x2222, 100);
	uint8_t before[256];
	memcpy(before, f, len);
	afr_mutate(f, len, 2, &cfg);
	CHECK_EQ(fold(sum16(f + 14, 20, 0)), 0);
	CHECK(memcmp(f + 34, before + 34, len - 34) == 0);
}

static void v6_cases(void)
{
	mutate_cfg_t cfg = {.ip = 1, .port = 1, .ip_offset = 0x00010000u, .port_step = 7};
	uint8_t protos[] = {6, 17};
	for (int i = 0; i < 2; i++) {
		uint8_t f[256], orig[256];
		uint32_t len = build_v6(f, protos[i]);
		memcpy(orig, f, len);
		CHECK(sums_ok(f, len));
		CHECK_EQ(afr_mutate(f, len, 4, &cfg), 1);
		CHECK(sums_ok(f, len));
		CHECK(memcmp(f, orig, 14) == 0);
		CHECK(memcmp(f + 14 + 8, orig + 14 + 8, 8) == 0); /* префикс /64 не меняется */
		CHECK(memcmp(f + 14 + 16, orig + 14 + 16, 8) != 0);
		CHECK_EQ(rd16(f + 54), 50000 + 28);
	}
}

static void only_ports(void)
{
	mutate_cfg_t cfg = {.ip = 0, .port = 1, .port_step = 100};
	uint8_t f[256], orig[256];
	uint32_t len = build_v4(f, 1, 6, 0x0a000001, 0x0a000002, 2000, 80, 0);
	memcpy(orig, f, len);
	afr_mutate(f, len, 1, &cfg);
	CHECK(sums_ok(f, len));
	CHECK(memcmp(f + 18, orig + 18, 20) == 0); /* IP-заголовок не изменился */
	CHECK_EQ(rd16(f + 38), 2100);
	/* не-IP кадр не трогается */
	uint8_t arp[60] = {0};
	arp[12] = 0x08;
	arp[13] = 0x06;
	CHECK_EQ(afr_mutate(arp, 60, 1, &cfg), 0);
}

static void rfc1624(void)
{
	/* Пример из RFC 1624, раздел 4: HC=0xDD2F, m=0x5555 -> m'=0x3285, HC'=0x0000 */
	CHECK_EQ(afr_csum_update16(0xDD2F, 0x5555, 0x3285), 0x0000);
}

void test_mutate(void)
{
	rfc1624();
	v4_cases();
	fragments();
	v6_cases();
	only_ports();
}
