//! Minimal parallel-for over contiguous chunks, used to parallelize the preparation
//! phases (timeline normalization, sorting, rate profile). Each call spawns its threads
//! and joins them; the phases are long enough that this costs nothing.

/// Below this many items a phase runs in one thread.
pub const PAR_MIN_ITEMS: usize = 1 << 16;
const PAR_MAX_THREADS: usize = 256;

/// Thread count to use for n items (1 for small inputs or want <= 1).
pub fn par_threads(want: usize, n: usize) -> usize {
    if want <= 1 || n < PAR_MIN_ITEMS {
        return 1;
    }
    let want = want.min(PAR_MAX_THREADS);
    let by_size = n / (PAR_MIN_ITEMS / 4);
    if by_size < want {
        by_size.max(1)
    } else {
        want
    }
}

/// Chunk t of [0, n) split into nt contiguous chunks whose boundaries are multiples of align.
pub fn par_range(nt: usize, n: usize, align: usize, t: usize) -> (usize, usize) {
    if nt <= 1 {
        return (0, n);
    }
    let align = align.max(1);
    let per = n.div_ceil(nt);
    let per = per.div_ceil(align) * align;
    let s = t * per;
    let a = s.min(n);
    let b = (a + per).min(n);
    (a, b)
}

/// Run f(t, a, b) on every chunk; chunk 0 runs in the calling thread.
pub fn par_for<F>(nt: usize, n: usize, align: usize, f: F)
where
    F: Fn(usize, usize, usize) + Sync,
{
    if nt <= 1 {
        f(0, 0, n);
        return;
    }
    let nt = nt.min(PAR_MAX_THREADS);
    std::thread::scope(|s| {
        let f = &f;
        let mut inline = Vec::new();
        let mut handles = Vec::new();
        for t in 1..nt {
            let (a, b) = par_range(nt, n, align, t);
            match std::thread::Builder::new().spawn_scoped(s, move || f(t, a, b)) {
                Ok(h) => handles.push(h),
                Err(_) => inline.push(t), // could not start a thread: run inline
            }
        }
        let (a, b) = par_range(nt, n, align, 0);
        f(0, a, b);
        for h in handles {
            let _ = h.join();
        }
        for t in inline {
            let (a, b) = par_range(nt, n, align, t);
            f(t, a, b);
        }
    });
}

/// par_for with a per-chunk state: f(&mut chunks[t], t, a, b).
pub fn par_for_each<C, F>(nt: usize, n: usize, align: usize, chunks: &mut [C], f: F)
where
    C: Send,
    F: Fn(&mut C, usize, usize, usize) + Sync,
{
    let p = crate::SyncPtr(chunks.as_mut_ptr());
    assert!(chunks.len() >= nt.max(1));
    // Each chunk index is visited by exactly one invocation.
    par_for(nt, n, align, |t, a, b| f(unsafe { &mut *p.get(t) }, t, a, b));
}
