/*
 * Модификация кадров на кругах зацикливания: сдвиг IP-адресов и/или портов
 * с инкрементальным пересчётом контрольных сумм (RFC 1624). L2 не меняется.
 */
#ifndef AFR_MUTATE_H
#define AFR_MUTATE_H

#include "afr.h"

typedef struct {
	int ip, port;
	uint32_t ip_offset; /* в порядке хоста, умножается на номер круга */
	uint32_t port_step;
	int raw_ip;         /* как разбирать кадр (см. afr_dissect); для кадра в кольце 0 */
} mutate_cfg_t;

/* Изменить кадр на месте для круга lap (> 0). Возвращает 1, если кадр изменён. */
int afr_mutate(uint8_t *frame, uint32_t len, uint64_t lap, const mutate_cfg_t *cfg);

/* Инкрементальное обновление 16-битной контрольной суммы (RFC 1624, ур. 3). */
static inline uint16_t afr_csum_update16(uint16_t hc, uint16_t old, uint16_t new_)
{
	uint32_t s = (uint16_t)~hc + (uint16_t)~old + (uint32_t)new_;
	s = (s & 0xFFFF) + (s >> 16);
	s = (s & 0xFFFF) + (s >> 16);
	return (uint16_t)~s;
}

#endif
