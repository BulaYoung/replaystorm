#ifndef AFR_UTIL_H
#define AFR_UTIL_H

#include "afr.h"

/* "1.5s", "10ms", "200us", "500ns", "2m", "1h"; a number without a suffix means seconds. */
int afr_parse_duration(const char *s, int64_t *ns);
/* "25G", "10000M", "1.5g"; a number without a suffix means bit/s. */
int afr_parse_bitrate(const char *s, double *bps);
int afr_parse_double(const char *s, double *v);
int afr_parse_u64(const char *s, uint64_t *v);
int afr_parse_mac(const char *s, uint8_t mac[6]);
int afr_parse_ipv4(const char *s, uint32_t *host_order);

/* CPU list of the form "0-3,8,10-11". Returns the number of CPUs or -1. */
int afr_parse_cpulist(const char *s, int *cpus, int max);
/* CPUs of the NIC's NUMA node (or all CPUs available to the process). */
int afr_iface_cpus(const char *iface, int *cpus, int max, int *from_numa);

int afr_sysfs_read_u64(const char *iface, const char *attr, uint64_t *v);
int afr_iface_mtu(const char *iface, unsigned *mtu);
/* Link speed in bit/s; -1 if unknown. */
int afr_iface_speed(const char *iface, double *bps);

/* Formatting */
void afr_fmt_bps(char *buf, size_t n, double bps);   /* "23.41 Gbit/s" */
void afr_fmt_ns(char *buf, size_t n, double ns);     /* "1.20 us" / "3.4 ms" */
void afr_fmt_count(char *buf, size_t n, double v);   /* "1.23 M" */
void afr_fmt_abs_ts(char *buf, size_t n, int64_t ns); /* "2024-05-01 12:00:03.123456789 UTC" */
int64_t afr_realtime_ns(void);

#endif
