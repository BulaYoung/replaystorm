#ifndef AFR_UTIL_H
#define AFR_UTIL_H

#include "afr.h"

/* "1.5s", "10ms", "200us", "500ns", "2m", "1h"; число без суффикса — секунды. */
int afr_parse_duration(const char *s, int64_t *ns);
/* "25G", "10000M", "1.5g"; число без суффикса — бит/с. */
int afr_parse_bitrate(const char *s, double *bps);
int afr_parse_double(const char *s, double *v);
int afr_parse_u64(const char *s, uint64_t *v);
int afr_parse_mac(const char *s, uint8_t mac[6]);
int afr_parse_ipv4(const char *s, uint32_t *host_order);

/* Список CPU вида "0-3,8,10-11". Возвращает число CPU или -1. */
int afr_parse_cpulist(const char *s, int *cpus, int max);
/* CPU NUMA-узла карты (или все доступные процессу). */
int afr_iface_cpus(const char *iface, int *cpus, int max, int *from_numa);

int afr_sysfs_read_u64(const char *iface, const char *attr, uint64_t *v);
int afr_iface_mtu(const char *iface, unsigned *mtu);
/* Скорость линка в бит/с; -1, если неизвестна. */
int afr_iface_speed(const char *iface, double *bps);

/* Форматирование */
void afr_fmt_bps(char *buf, size_t n, double bps);   /* "23.41 Гбит/с" */
void afr_fmt_ns(char *buf, size_t n, double ns);     /* "1.20 мкс" / "3.4 мс" */
void afr_fmt_count(char *buf, size_t n, double v);   /* "1.23 M" */
void afr_fmt_abs_ts(char *buf, size_t n, int64_t ns); /* "2024-05-01 12:00:03.123456789 UTC" */
int64_t afr_realtime_ns(void);

#endif
