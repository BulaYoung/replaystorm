/*
 * Разбор кадра: L2 (VLAN/QinQ/MPLS/PPPoE) -> L3 -> L4 и симметричный хеш потока.
 */
#ifndef AFR_DISSECT_H
#define AFR_DISSECT_H

#include "afr.h"

#define ETH_HLEN_ 14
#define ETHT_IPV4 0x0800
#define ETHT_ARP 0x0806
#define ETHT_VLAN 0x8100
#define ETHT_QINQ 0x88a8
#define ETHT_QINQ_OLD1 0x9100
#define ETHT_QINQ_OLD2 0x9200
#define ETHT_IPV6 0x86dd
#define ETHT_MPLS_UC 0x8847
#define ETHT_MPLS_MC 0x8848
#define ETHT_PPPOE_S 0x8864
#define ETHT_LLDP 0x88cc

/* Вид не-IP кадра (для статистики). */
enum {
	L2K_IP = 0,
	L2K_ARP,
	L2K_LLC,  /* 802.3 + LLC: STP, CDP и т.п. */
	L2K_LLDP,
	L2K_OTHER,
	L2K_COUNT
};

typedef struct {
	uint8_t l3;          /* 0 — не IP, 4 или 6 */
	uint8_t proto;       /* L4-протокол (после заголовков расширения IPv6) */
	uint8_t frag;        /* 1 — фрагмент (любой) */
	uint8_t frag_first;  /* 1 — первый фрагмент (offset == 0) или не фрагмент */
	uint8_t vlan_depth;  /* число VLAN-тегов */
	uint8_t mpls;        /* 1 — был стек MPLS */
	uint8_t pppoe;
	uint8_t l2kind;
	uint16_t outer_ethertype; /* ethertype сразу после MAC-адресов */
	uint16_t l3_off;     /* смещение L3 в кадре */
	uint16_t l4_off;     /* смещение L4, 0 если нет */
	uint16_t sport, dport; /* в порядке хоста; 0 если нет портов */
	const uint8_t *src, *dst; /* адреса L3 (4 или 16 байт) */
} dis_t;

/*
 * Разобрать кадр. raw_ip: 0 — кадр начинается с Ethernet, 4/6 — с IP указанной
 * версии, 1 — с IP, версия из первого полубайта.
 */
void afr_dissect(const uint8_t *p, uint32_t len, int raw_ip, dis_t *d);

/* Симметричный хеш потока: A->B и B->A дают одно значение. Только для d->l3 != 0. */
uint64_t afr_flow_hash(const dis_t *d);

#endif
