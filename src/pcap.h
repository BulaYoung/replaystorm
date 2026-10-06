/*
 * Разбор классического pcap, отображённого в память.
 */
#ifndef AFR_PCAP_H
#define AFR_PCAP_H

#include "afr.h"

#define LINKTYPE_ETHERNET 1
#define LINKTYPE_RAW 101
#define LINKTYPE_IPV4 228
#define LINKTYPE_IPV6 229
#define LINKTYPE_RAW_OLD 12 /* DLT_RAW на некоторых платформах */

/* Максимальный разумный caplen одной записи: больше — значит файл повреждён. */
#define PCAP_MAX_CAPLEN (256u * 1024u)
#define PCAP_FILE_HDR_LEN 24u
#define PCAP_REC_HDR_LEN 16u

typedef struct {
	int fd;
	const uint8_t *base;
	size_t size;
	int swapped;       /* порядок байт файла отличается от нашего */
	int nsec;          /* наносекундные метки */
	uint32_t linktype; /* без битов FCS */
	uint32_t snaplen;
	int raw_ip;        /* 0 — Ethernet, 4/6 — фиксированная версия, 1 — версия из пакета */
	int preloaded;
} pcap_file_t;

/* Одна запись pcap. */
typedef struct {
	uint64_t data_off; /* смещение данных пакета от начала файла */
	uint32_t caplen;
	uint32_t origlen;
	int64_t ts_ns; /* абсолютное время, нс */
} pcap_rec_t;

enum {
	PCAP_REC_OK = 0,
	PCAP_REC_END = 1,       /* аккуратный конец файла */
	PCAP_REC_TRUNCATED = 2, /* файл обрезан посреди записи */
	PCAP_REC_CORRUPT = 3,   /* бессмысленный заголовок записи */
};

/* Открыть и отобразить файл. Возвращает 0 или -1 с текстом ошибки в err. */
int pcap_open(pcap_file_t *pf, const char *path, int preload, char *err, size_t errlen);
/* Разобрать заголовок уже отображённого буфера (используется и в тестах). */
int pcap_parse_header(pcap_file_t *pf, char *err, size_t errlen);
void pcap_close(pcap_file_t *pf);

/* Прочитать запись по смещению *off; при успехе сдвигает *off на следующую. */
static inline uint32_t pcap_u32(const pcap_file_t *pf, const uint8_t *p)
{
	uint32_t v;
	__builtin_memcpy(&v, p, 4);
	return pf->swapped ? __builtin_bswap32(v) : v;
}

static inline int pcap_next(const pcap_file_t *pf, uint64_t *off, pcap_rec_t *r)
{
	uint64_t o = *off;
	if (o == pf->size)
		return PCAP_REC_END;
	if (o + PCAP_REC_HDR_LEN > pf->size)
		return PCAP_REC_TRUNCATED;
	const uint8_t *h = pf->base + o;
	uint32_t sec = pcap_u32(pf, h);
	uint32_t frac = pcap_u32(pf, h + 4);
	r->caplen = pcap_u32(pf, h + 8);
	r->origlen = pcap_u32(pf, h + 12);
	if (r->caplen > PCAP_MAX_CAPLEN)
		return PCAP_REC_CORRUPT;
	if (o + PCAP_REC_HDR_LEN + r->caplen > pf->size)
		return PCAP_REC_TRUNCATED;
	r->data_off = o + PCAP_REC_HDR_LEN;
	r->ts_ns = (int64_t)sec * NS_PER_SEC + (pf->nsec ? (int64_t)frac : (int64_t)frac * 1000);
	*off = r->data_off + r->caplen;
	return PCAP_REC_OK;
}

const char *pcap_linktype_name(uint32_t lt);

#endif
