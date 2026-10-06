/*
 * Frame dissection: L2 (VLAN/QinQ/MPLS/PPPoE) -> L3 -> L4, plus a symmetric flow hash.
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

/* Kind of non-IP frame (for statistics). */
enum {
	L2K_IP = 0,
	L2K_ARP,
	L2K_LLC,  /* 802.3 + LLC: STP, CDP, etc. */
	L2K_LLDP,
	L2K_OTHER,
	L2K_COUNT
};

typedef struct {
	uint8_t l3;          /* 0 = not IP, 4 or 6 */
	uint8_t proto;       /* L4 protocol (after IPv6 extension headers) */
	uint8_t frag;        /* 1 = fragment (any) */
	uint8_t frag_first;  /* 1 = first fragment (offset == 0) or not a fragment */
	uint8_t vlan_depth;  /* number of VLAN tags */
	uint8_t mpls;        /* 1 = MPLS stack present */
	uint8_t pppoe;
	uint8_t l2kind;
	uint16_t outer_ethertype; /* ethertype right after the MAC addresses */
	uint16_t l3_off;     /* L3 offset in the frame */
	uint16_t l4_off;     /* L4 offset, 0 if none */
	uint16_t sport, dport; /* host byte order; 0 if no ports */
	const uint8_t *src, *dst; /* L3 addresses (4 or 16 bytes) */
} dis_t;

/*
 * Dissect a frame. raw_ip: 0 = frame starts with Ethernet, 4/6 = with IP of the given
 * version, 1 = with IP, version taken from the first nibble.
 */
void afr_dissect(const uint8_t *p, uint32_t len, int raw_ip, dis_t *d);

/* Symmetric flow hash: A->B and B->A yield the same value. Only for d->l3 != 0. */
uint64_t afr_flow_hash(const dis_t *d);

#endif
