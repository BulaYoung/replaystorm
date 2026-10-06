/*
 * afreplay — многопоточный реплеер pcap через AF_PACKET.
 * Общие определения.
 */
#ifndef AFR_H
#define AFR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define AFR_CACHELINE 64
#define AFR_ALIGNED __attribute__((aligned(AFR_CACHELINE)))
#define AFR_LIKELY(x) __builtin_expect(!!(x), 1)
#define AFR_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define AFR_UNUSED __attribute__((unused))
#define AFR_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define NS_PER_SEC 1000000000LL
#define NS_PER_MS 1000000LL
#define NS_PER_US 1000LL

/* Смещение в файле (48 бит) и длина кадра (16 бит) упакованы в одно слово. */
#define OFFLEN_MAKE(off, len) (((uint64_t)(len) << 48) | ((uint64_t)(off) & 0xFFFFFFFFFFFFULL))
#define OFFLEN_OFF(v) ((v) & 0xFFFFFFFFFFFFULL)
#define OFFLEN_LEN(v) ((uint32_t)((v) >> 48))

/* Запись индекса шарда: 16 байт. ts — время по шкале расписания (нс от начала). */
typedef struct {
	int64_t ts;
	uint64_t offlen;
} pkt_t;

/* Специальные значения номера шарда в глобальном индексе. */
#define SHARD_SKIP 0xFFFFu

/* Причины пропуска кадров. */
enum {
	SKIP_TOO_BIG = 0, /* больше MTU + заголовок */
	SKIP_TOO_SMALL,   /* меньше заголовка Ethernet */
	SKIP_BAD_RAW,     /* RAW IP без версии 4/6 */
	SKIP_REASONS
};

static inline int64_t afr_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static inline void afr_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#elif defined(__aarch64__)
	__asm__ __volatile__("yield" ::: "memory");
#else
	__asm__ __volatile__("" ::: "memory");
#endif
}

void afr_log_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void afr_log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void afr_log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern int afr_quiet;

#endif
