#include "t.h"

int t_failed, t_checks;

int main(void)
{
	struct {
		const char *name;
		void (*fn)(void);
	} suites[] = {
	    {"парсер pcap", test_pcap},
	    {"хеш и шардирование", test_hash},
	    {"расписание", test_sched},
	    {"модификация на круге", test_mutate},
	};
	for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
		int before = t_failed;
		suites[i].fn();
		printf("%s: %s\n", suites[i].name, t_failed == before ? "OK" : "ОШИБКИ");
	}
	printf("проверок: %d, не пройдено: %d\n", t_checks, t_failed);
	return t_failed ? 1 : 0;
}
