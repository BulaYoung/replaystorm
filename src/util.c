#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <sched.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

int afr_quiet = 0;

void afr_log_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("afreplay: error: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

void afr_log_warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("WARNING: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

void afr_log_info(const char *fmt, ...)
{
	if (afr_quiet)
		return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	fputc('\n', stdout);
	va_end(ap);
	fflush(stdout);
}

int afr_parse_double(const char *s, double *v)
{
	char *end;
	errno = 0;
	double d = strtod(s, &end);
	if (errno || end == s || *end || !isfinite(d))
		return -1;
	*v = d;
	return 0;
}

int afr_parse_u64(const char *s, uint64_t *v)
{
	char *end;
	errno = 0;
	if (*s == '-')
		return -1;
	unsigned long long x = strtoull(s, &end, 10);
	if (errno || end == s || *end)
		return -1;
	*v = x;
	return 0;
}

int afr_parse_duration(const char *s, int64_t *ns)
{
	char *end;
	errno = 0;
	double d = strtod(s, &end);
	if (errno || end == s || d < 0 || !isfinite(d))
		return -1;
	double m;
	if (!*end || !strcmp(end, "s"))
		m = 1e9;
	else if (!strcmp(end, "ms"))
		m = 1e6;
	else if (!strcmp(end, "us"))
		m = 1e3;
	else if (!strcmp(end, "ns"))
		m = 1;
	else if (!strcmp(end, "m"))
		m = 60e9;
	else if (!strcmp(end, "h"))
		m = 3600e9;
	else
		return -1;
	double r = d * m;
	if (r > 9e18)
		return -1;
	*ns = (int64_t)llround(r);
	return 0;
}

int afr_parse_bitrate(const char *s, double *bps)
{
	char *end;
	errno = 0;
	double d = strtod(s, &end);
	if (errno || end == s || d <= 0 || !isfinite(d))
		return -1;
	double m = 1;
	if (!*end)
		m = 1;
	else if (!strcasecmp(end, "k"))
		m = 1e3;
	else if (!strcasecmp(end, "m"))
		m = 1e6;
	else if (!strcasecmp(end, "g"))
		m = 1e9;
	else
		return -1;
	*bps = d * m;
	return 0;
}

int afr_parse_mac(const char *s, uint8_t mac[6])
{
	unsigned v[6];
	char tail;
	if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (v[i] > 0xFF)
			return -1;
		mac[i] = (uint8_t)v[i];
	}
	return 0;
}

int afr_parse_ipv4(const char *s, uint32_t *host_order)
{
	struct in_addr a;
	if (inet_pton(AF_INET, s, &a) != 1)
		return -1;
	*host_order = ntohl(a.s_addr);
	return 0;
}

int afr_parse_cpulist(const char *s, int *cpus, int max)
{
	int n = 0;
	const char *p = s;
	while (*p) {
		while (*p == ' ' || *p == '\n')
			p++;
		if (!*p)
			break;
		char *end;
		long a = strtol(p, &end, 10);
		if (end == p || a < 0)
			return -1;
		long b = a;
		p = end;
		if (*p == '-') {
			p++;
			b = strtol(p, &end, 10);
			if (end == p || b < a)
				return -1;
			p = end;
		}
		for (long c = a; c <= b; c++) {
			if (n >= max)
				return -1;
			cpus[n++] = (int)c;
		}
		while (*p == ' ' || *p == '\n')
			p++;
		if (*p == ',')
			p++;
		else if (*p)
			return -1;
	}
	return n;
}

static int read_sysfs(const char *path, char *buf, size_t n)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	size_t r = fread(buf, 1, n - 1, f);
	int bad = ferror(f);
	fclose(f);
	if (bad || r == 0)
		return -1;
	buf[r] = 0;
	return 0;
}

int afr_iface_cpus(const char *iface, int *cpus, int max, int *from_numa)
{
	char path[256], buf[4096];
	*from_numa = 0;
	cpu_set_t allowed;
	CPU_ZERO(&allowed);
	sched_getaffinity(0, sizeof(allowed), &allowed);
	if (iface) {
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/local_cpulist", iface);
		if (read_sysfs(path, buf, sizeof(buf)) == 0) {
			int tmp[1024];
			int k = afr_parse_cpulist(buf, tmp, 1024);
			int n = 0;
			for (int i = 0; i < k && n < max; i++)
				if (tmp[i] < CPU_SETSIZE && CPU_ISSET(tmp[i], &allowed))
					cpus[n++] = tmp[i];
			if (n > 0) {
				*from_numa = 1;
				return n;
			}
		}
	}
	int n = 0;
	for (int c = 0; c < CPU_SETSIZE && n < max; c++)
		if (CPU_ISSET(c, &allowed))
			cpus[n++] = c;
	return n;
}

int afr_sysfs_read_str(const char *iface, const char *attr, char *buf, size_t n)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", iface, attr);
	if (read_sysfs(path, buf, n) < 0)
		return -1;
	buf[strcspn(buf, "\n")] = 0;
	return 0;
}

int afr_sysfs_read_u64(const char *iface, const char *attr, uint64_t *v)
{
	char path[256], buf[64];
	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", iface, attr);
	if (read_sysfs(path, buf, sizeof(buf)) < 0)
		return -1;
	char *end;
	errno = 0;
	long long x = strtoll(buf, &end, 10);
	if (errno || end == buf || x < 0)
		return -1;
	*v = (uint64_t)x;
	return 0;
}

int afr_iface_mtu(const char *iface, unsigned *mtu)
{
	uint64_t v;
	if (afr_sysfs_read_u64(iface, "mtu", &v) < 0 || v == 0 || v > 65535)
		return -1;
	*mtu = (unsigned)v;
	return 0;
}

int afr_iface_speed(const char *iface, double *bps)
{
	/* /sys/.../speed reports the same value as ethtool (Mbit/s). */
	uint64_t v;
	if (afr_sysfs_read_u64(iface, "speed", &v) < 0 || v == 0 || v >= 0xFFFFFFFFull)
		return -1;
	*bps = (double)v * 1e6;
	return 0;
}

void afr_fmt_bps(char *buf, size_t n, double bps)
{
	if (bps >= 1e9)
		snprintf(buf, n, "%.2f Gbit/s", bps / 1e9);
	else if (bps >= 1e6)
		snprintf(buf, n, "%.2f Mbit/s", bps / 1e6);
	else if (bps >= 1e3)
		snprintf(buf, n, "%.2f Kbit/s", bps / 1e3);
	else
		snprintf(buf, n, "%.0f bit/s", bps);
}

void afr_fmt_ns(char *buf, size_t n, double ns)
{
	double a = fabs(ns);
	if (a >= 86400e9)
		snprintf(buf, n, "%.2f days", ns / 86400e9);
	else if (a >= 3600e9)
		snprintf(buf, n, "%.2f h", ns / 3600e9);
	else if (a >= 1e9)
		snprintf(buf, n, "%.3f s", ns / 1e9);
	else if (a >= 1e6)
		snprintf(buf, n, "%.2f ms", ns / 1e6);
	else if (a >= 1e3)
		snprintf(buf, n, "%.2f us", ns / 1e3);
	else
		snprintf(buf, n, "%.0f ns", ns);
}

void afr_fmt_count(char *buf, size_t n, double v)
{
	if (v >= 1e9)
		snprintf(buf, n, "%.2f G", v / 1e9);
	else if (v >= 1e6)
		snprintf(buf, n, "%.2f M", v / 1e6);
	else if (v >= 1e3)
		snprintf(buf, n, "%.2f K", v / 1e3);
	else
		snprintf(buf, n, "%.0f", v);
}

void afr_fmt_abs_ts(char *buf, size_t n, int64_t ns)
{
	time_t sec = (time_t)(ns / NS_PER_SEC);
	long frac = (long)(ns % NS_PER_SEC);
	if (frac < 0) {
		frac += NS_PER_SEC;
		sec--;
	}
	struct tm tm;
	if (!gmtime_r(&sec, &tm)) {
		snprintf(buf, n, "%lld ns", (long long)ns);
		return;
	}
	char d[64];
	strftime(d, sizeof(d), "%Y-%m-%d %H:%M:%S", &tm);
	snprintf(buf, n, "%s.%09ld UTC", d, frac);
}

int64_t afr_realtime_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

int afr_parse_size(const char *s, uint64_t *bytes)
{
	char *end;
	errno = 0;
	double d = strtod(s, &end);
	if (errno || end == s || d < 0 || !isfinite(d))
		return -1;
	double m = 1;
	if (!*end)
		m = 1;
	else if (!strcasecmp(end, "k"))
		m = 1024.0;
	else if (!strcasecmp(end, "m"))
		m = 1024.0 * 1024;
	else if (!strcasecmp(end, "g"))
		m = 1024.0 * 1024 * 1024;
	else
		return -1;
	*bytes = (uint64_t)(d * m);
	return 0;
}

uint64_t afr_mem_available(void)
{
	uint64_t kb = 0;
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f)
		return 0;
	char line[256];
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "MemAvailable: %" SCNu64 " kB", &kb) == 1)
			break;
	fclose(f);
	return kb * 1024;
}
