#include "par.h"

#include <pthread.h>
#include <stdlib.h>

#define PAR_MAX_THREADS 256

unsigned afr_par_threads(unsigned want, size_t n)
{
	if (want <= 1 || n < AFR_PAR_MIN_ITEMS)
		return 1;
	if (want > PAR_MAX_THREADS)
		want = PAR_MAX_THREADS;
	size_t by_size = n / (AFR_PAR_MIN_ITEMS / 4);
	return by_size < want ? (unsigned)(by_size ? by_size : 1) : want;
}

void afr_par_range(unsigned nt, size_t n, size_t align, unsigned t, size_t *a, size_t *b)
{
	if (nt <= 1) {
		*a = 0;
		*b = n;
		return;
	}
	if (align == 0)
		align = 1;
	size_t per = (n + nt - 1) / nt;
	per = (per + align - 1) / align * align;
	size_t s = (size_t)t * per;
	*a = s < n ? s : n;
	*b = *a + per < n ? *a + per : n;
}

typedef struct {
	afr_par_fn fn;
	void *ctx;
	unsigned t;
	size_t a, b;
	pthread_t th;
	int started;
} par_job_t;

static void *par_main(void *arg)
{
	par_job_t *j = arg;
	j->fn(j->ctx, j->t, j->a, j->b);
	return NULL;
}

void afr_par_for(unsigned nt, size_t n, size_t align, afr_par_fn fn, void *ctx)
{
	if (nt <= 1) {
		fn(ctx, 0, 0, n);
		return;
	}
	par_job_t jobs[PAR_MAX_THREADS];
	if (nt > PAR_MAX_THREADS)
		nt = PAR_MAX_THREADS;
	for (unsigned t = 0; t < nt; t++) {
		jobs[t] = (par_job_t){.fn = fn, .ctx = ctx, .t = t};
		afr_par_range(nt, n, align, t, &jobs[t].a, &jobs[t].b);
	}
	for (unsigned t = 1; t < nt; t++)
		jobs[t].started = pthread_create(&jobs[t].th, NULL, par_main, &jobs[t]) == 0;
	fn(ctx, 0, jobs[0].a, jobs[0].b);
	for (unsigned t = 1; t < nt; t++) {
		if (jobs[t].started)
			pthread_join(jobs[t].th, NULL);
		else
			fn(ctx, t, jobs[t].a, jobs[t].b); /* could not start a thread: run inline */
	}
}
