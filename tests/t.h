/* Minimal unit test framework. */
#ifndef AFR_T_H
#define AFR_T_H

#include <inttypes.h>
#include <stdio.h>

extern int t_failed, t_checks;

#define CHECK(cond)                                                                    \
	do {                                                                               \
		t_checks++;                                                                    \
		if (!(cond)) {                                                                 \
			t_failed++;                                                                \
			fprintf(stderr, "  FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
		}                                                                              \
	} while (0)

#define CHECK_EQ(a, b)                                                                 \
	do {                                                                               \
		long long _a = (long long)(a), _b = (long long)(b);                            \
		t_checks++;                                                                    \
		if (_a != _b) {                                                                \
			t_failed++;                                                                \
			fprintf(stderr, "  FAILED %s:%d: %s == %s (%lld != %lld)\n", __FILE__, \
			        __LINE__, #a, #b, _a, _b);                                         \
		}                                                                              \
	} while (0)

void test_pcap(void);
void test_hash(void);
void test_sched(void);
void test_mutate(void);
void test_therm(void);
void test_live(void);

#endif
