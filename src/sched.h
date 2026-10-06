/*
 * Расписание отправки: нормализация тайм-стампов, расчёт времени отправки,
 * профиль скорости. Все функции чистые (без глобального состояния) и
 * покрыты юнит-тестами.
 */
#ifndef AFR_SCHED_H
#define AFR_SCHED_H

#include "afr.h"

/* ---------- Стабильная поразрядная сортировка 16-байтных записей ---------- */

typedef struct {
	int64_t key;
	uint64_t val;
} rec16_t;

/* Стабильно сортирует a[0..n) по знаковому key; tmp — буфер того же размера. */
void afr_radix_sort16(rec16_t *a, rec16_t *tmp, size_t n);

/* ---------- Нормализация тайм-стампов ---------- */

enum { TS_ORDER_ASIS = 0, TS_ORDER_CLAMP, TS_ORDER_SORT };

typedef struct {
	int order;            /* TS_ORDER_* */
	int64_t max_gap;      /* сжимать паузы длиннее этого значения, нс (0 — нет) */
	int exclude_outliers; /* исключить выбросы из шкалы */
	int64_t outlier_jump; /* порог скачка часов, нс (0 — не искать скачки) */
	int64_t now_ns;       /* текущее время UTC, нс — для поиска «будущих» меток */
} ts_cfg_t;

#define TS_TOP_GAPS 10
#define TS_SPIKE_LOOKAHEAD 16
#define TS_PAST_LIMIT_NS (631152000LL * NS_PER_SEC) /* 1990-01-01 */
#define TS_FUTURE_SLACK_NS (86400LL * NS_PER_SEC)

typedef struct {
	int64_t at;    /* абсолютная метка начала паузы */
	int64_t len;   /* длина паузы, нс */
	uint64_t idx;  /* номер пакета после паузы (по порядку в файле), если известен */
	int idx_known;
} ts_gap_t;

typedef struct {
	uint64_t n;         /* пакетов на шкале (без пропущенных) */
	int64_t first_abs;  /* метка первого пакета (по порядку в файле) */
	int64_t min_abs, max_abs;
	int64_t base_abs;   /* точка отсчёта шкалы */
	/* немонотонность (по порядку в файле, относительно накопленного максимума) */
	uint64_t backward;
	int64_t max_backward;
	uint64_t max_backward_idx;
	/* выбросы */
	uint64_t outl_zero, outl_past, outl_future, outl_spike;
	uint64_t outliers;
	int excluded;
	/* паузы */
	uint64_t gaps_over;   /* сколько пауз длиннее max_gap */
	int64_t gap_removed;  /* сколько времени вырезано */
	ts_gap_t top[TS_TOP_GAPS];
	int ntop;
	/* итог */
	int monotone;         /* шкала неубывающая по порядку в файле */
	int64_t duration;     /* длительность шкалы (нс) */
	int64_t lap_len;      /* длина одного круга при зацикливании (нс) */
} ts_result_t;

/*
 * Превращает абсолютные метки ts[] (нс) в шкалу расписания (нс от начала, с
 * учётом clamp, выбросов и max-gap). shard[i] == SHARD_SKIP — пакет не
 * участвует (shard может быть NULL). Порядок пакетов не меняется: при
 * order=sort сортировка делается позже, внутри каждого шарда. Возвращает 0
 * или -1 при нехватке памяти.
 */
int afr_ts_normalize(int64_t *ts, const uint16_t *shard, size_t n, const ts_cfg_t *cfg,
                     ts_result_t *res);

/* Время отправки: T0 + (номер_круга * длина_круга + ts) / множитель. */
static inline int64_t afr_target(int64_t t0, uint64_t lap, int64_t lap_len, int64_t sched,
                                 double inv_mult)
{
	return t0 + (int64_t)(((double)lap * (double)lap_len + (double)sched) * inv_mult);
}

/* ---------- Профиль скорости ---------- */

#define RATE_WINDOWS 3
extern const int64_t afr_rate_windows_ns[RATE_WINDOWS]; /* 1 мс, 10 мс, 1 с */
extern const char *const afr_rate_window_names[RATE_WINDOWS];

typedef struct {
	double mult;         /* множитель скорости */
	int64_t timing_res;  /* достижимая точность тайминга, нс */
	uint32_t l2_extra;   /* байт добавляется к каждому кадру (синтетический Ethernet) */
	unsigned nshards;    /* число шардов (включая не-IP) */
} rate_cfg_t;

typedef struct {
	uint64_t pkts, bytes;
	double wall_duration_s;               /* длительность после множителя */
	double avg_bps;
	double peak_bps[RATE_WINDOWS];        /* L2 (байты кадра) */
	double peak_l1_bps[RATE_WINDOWS];     /* с преамбулой, IFG и FCS */
	uint64_t gaps_total;                  /* интервалов внутри шардов */
	uint64_t gaps_below_res;              /* из них короче timing_res */
	uint64_t gaps_lt[3];                  /* < 1 мкс, < 10 мкс, < 100 мкс */
} rate_result_t;

/* Байт на линии сверх кадра: преамбула 8 + IFG 12 + FCS 4; минимум кадра 60. */
static inline uint64_t afr_l1_bytes(uint32_t frame_len)
{
	return (uint64_t)(frame_len < 60 ? 60 : frame_len) + 24;
}

int afr_rate_profile(const int64_t *sched, const uint64_t *offlen, const uint16_t *shard, size_t n,
                     int monotone, const rate_cfg_t *cfg, rate_result_t *res);

/* ---------- Гистограмма опозданий (лог-линейная, без malloc) ---------- */

#define LH_SUB_BITS 3
#define LH_SUB (1u << LH_SUB_BITS)
#define LH_BUCKETS (64u * LH_SUB)

static inline unsigned afr_lh_bucket(uint64_t v)
{
	if (v < LH_SUB)
		return (unsigned)v;
	unsigned msb = 63u - (unsigned)__builtin_clzll(v);
	unsigned shift = msb - LH_SUB_BITS;
	return (msb - LH_SUB_BITS + 1) * LH_SUB + (unsigned)((v >> shift) & (LH_SUB - 1));
}

/* Верхняя граница значений корзины. */
uint64_t afr_lh_upper(unsigned b);
/* Значение q-квантиля (0..1) по гистограмме; 0, если пусто. */
uint64_t afr_lh_quantile(const uint64_t *hist, double q);

#endif
