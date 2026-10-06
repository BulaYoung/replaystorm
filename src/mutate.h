/*
 * Frame modification on loop laps: shifting IP addresses and/or ports
 * with incremental checksum update (RFC 1624). L2 is left unchanged.
 */
#ifndef AFR_MUTATE_H
#define AFR_MUTATE_H

#include "afr.h"

typedef struct {
	int ip, port;
	uint32_t ip_offset; /* host byte order, multiplied by the lap number */
	uint32_t port_step;
	int raw_ip;         /* how to parse the frame (see afr_dissect); 0 for a frame in the ring */
} mutate_cfg_t;

/* Modify the frame in place for lap (> 0). Returns 1 if the frame was changed. */
int afr_mutate(uint8_t *frame, uint32_t len, uint64_t lap, const mutate_cfg_t *cfg);

/* Incremental update of a 16-bit checksum (RFC 1624, eqn. 3). */
static inline uint16_t afr_csum_update16(uint16_t hc, uint16_t old, uint16_t new_)
{
	uint32_t s = (uint16_t)~hc + (uint16_t)~old + (uint32_t)new_;
	s = (s & 0xFFFF) + (s >> 16);
	s = (s & 0xFFFF) + (s >> 16);
	return (uint16_t)~s;
}

#endif
