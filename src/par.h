/*
 * Minimal parallel-for over contiguous chunks, used to parallelize the preparation
 * phases (timeline normalization, sorting, rate profile). Each call spawns its threads
 * and joins them; the phases are long enough that this costs nothing.
 */
#ifndef AFR_PAR_H
#define AFR_PAR_H

#include "afr.h"

typedef void (*afr_par_fn)(void *ctx, unsigned t, size_t a, size_t b);

/* Below this many items a phase runs in one thread. */
#define AFR_PAR_MIN_ITEMS (1u << 16)

/* Thread count to use for n items (1 for small inputs or want <= 1). */
unsigned afr_par_threads(unsigned want, size_t n);
/* Chunk t of [0, n) split into nt contiguous chunks whose boundaries are multiples of align. */
void afr_par_range(unsigned nt, size_t n, size_t align, unsigned t, size_t *a, size_t *b);
/* Run fn on every chunk; chunk 0 runs in the calling thread. */
void afr_par_for(unsigned nt, size_t n, size_t align, afr_par_fn fn, void *ctx);

#endif
