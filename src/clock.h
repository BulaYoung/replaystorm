/*
 * Быстрые часы для горячего цикла.
 *
 * Обычно CLOCK_MONOTONIC через vDSO стоит ~20 нс. Но если ядро перешло на
 * clocksource hpet/acpi_pm (TSC отбракован, бывает на ноутбуках и в ВМ), каждый
 * вызов стоит ~1 мкс. Тогда используем rdtsc: частота калибруется один раз по
 * CLOCK_MONOTONIC, смещение — в каждом потоке отдельно (на случай, если TSC
 * разных ядер не синхронизированы). Результат — наносекунды в той же шкале,
 * что CLOCK_MONOTONIC.
 */
#ifndef AFR_CLOCK_H
#define AFR_CLOCK_H

#include "afr.h"

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define AFR_HAVE_TSC 1
#else
#define AFR_HAVE_TSC 0
#endif

enum { CLOCK_MODE_AUTO = 0, CLOCK_MODE_TSC, CLOCK_MODE_MONO };

extern int afr_clk_use_tsc;
extern double afr_clk_ns_per_tick;
extern __thread uint64_t afr_clk_base_tick;
extern __thread int64_t afr_clk_base_ns;

/* Выбрать часы и откалибровать частоту TSC. Возвращает описание для лога. */
const char *afr_clock_init(int mode);
/* Привязать смещение TSC текущего потока к CLOCK_MONOTONIC. */
void afr_clock_thread_init(void);

static inline int64_t afr_clock_ns(void)
{
#if AFR_HAVE_TSC
	if (AFR_LIKELY(afr_clk_use_tsc))
		return afr_clk_base_ns +
		       (int64_t)((double)(__rdtsc() - afr_clk_base_tick) * afr_clk_ns_per_tick);
#endif
	return afr_now_ns();
}

#endif
