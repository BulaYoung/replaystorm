#include "t.h"

int t_failed, t_checks;

int main(void)
{
	struct {
		const char *name;
		void (*fn)(void);
	} suites[] = {
	    {"pcap parser", test_pcap},
	    {"hash and sharding", test_hash},
	    {"schedule", test_sched},
	    {"loop mutation", test_mutate},
	    {"thermal governor", test_therm},
	};
	for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
		int before = t_failed;
		suites[i].fn();
		printf("%s: %s\n", suites[i].name, t_failed == before ? "OK" : "FAILED");
	}
	printf("checks: %d, failed: %d\n", t_checks, t_failed);
	return t_failed ? 1 : 0;
}
