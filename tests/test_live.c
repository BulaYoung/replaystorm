#include "live.h"
#include "t.h"

#define S(x) ((int64_t)(x) * NS_PER_SEC)

void test_live(void)
{
	live_t l;
	CHECK_EQ(afr_live_init(&l, 25.0, 0, 0), 0);
	/* warm-up: the first 10 s are not counted */
	for (int s = 1; s < 10; s++)
		afr_live_add(&l, S(s), 1.0, 1.0, 0.1, 0);
	CHECK_EQ(l.seconds, 0);
	CHECK_EQ(l.excluded, 9);
	/* 100 s at 24, one second at 18 at t=50, a link outage second at 1.0 (excluded) */
	for (int s = 10; s < 110; s++) {
		double g = s == 50 ? 18.0 : 24.0;
		afr_live_add(&l, S(s), 1.0, g, 3.0, 0);
	}
	afr_live_add(&l, S(110), 1.0, 1.0, 0.1, 1);
	CHECK_EQ(l.seconds, 100);
	CHECK_EQ(l.excluded, 10);
	CHECK(l.min_gbps == 18.0);
	CHECK_EQ(l.min_at, S(50));
	CHECK(l.max_gbps == 24.0);
	CHECK_EQ(l.below_target, 1); /* < 95% of 25 = 23.75 */
	/* worst minute contains the 18 Gbit/s second: (59*24 + 18) / 60 */
	CHECK(l.worst_min_gbps > 23.89 && l.worst_min_gbps < 23.91);
	CHECK(afr_live_quantile(&l, 0.005) > 17.99 && afr_live_quantile(&l, 0.005) < 18.01);
	CHECK(afr_live_quantile(&l, 0.5) > 23.99 && afr_live_quantile(&l, 0.5) < 24.01);
	/* a partial interval is not counted either */
	afr_live_add(&l, S(111), 0.4, 5.0, 0.5, 0);
	CHECK_EQ(l.seconds, 100);
	/* reset forgets the minimum */
	afr_live_reset(&l, S(111));
	afr_live_add(&l, S(112), 1.0, 22.0, 3.0, 0);
	CHECK(l.min_gbps == 22.0);
	CHECK_EQ(l.seconds, 1);
	/* the worst minute needs 60 consecutive counted seconds */
	CHECK_EQ(l.worst_min_at, 0);
	afr_live_free(&l);
}
