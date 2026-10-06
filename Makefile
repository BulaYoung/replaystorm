# afreplay — многопоточный реплеер pcap через AF_PACKET
CC      ?= cc
CFLAGS  ?= -O2 -g
# Обязательные флаги отдельно, чтобы make CFLAGS=... их не терял
XCFLAGS := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -pthread -MMD -MP
LDLIBS  += -pthread -lm

BUILD   := build
SRCS    := $(filter-out src/main.c,$(wildcard src/*.c))
OBJS    := $(SRCS:src/%.c=$(BUILD)/%.o)
TESTSRC := $(wildcard tests/test_*.c)

.PHONY: all clean test unit-test func-test pcaps sanitize

all: afreplay

afreplay: $(OBJS) $(BUILD)/main.o
	$(CC) $(XCFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(XCFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD)/tests/%.o: tests/%.c | $(BUILD)
	@mkdir -p $(BUILD)/tests
	$(CC) $(XCFLAGS) $(CFLAGS) -Isrc -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/unit_tests: $(TESTSRC:tests/%.c=$(BUILD)/tests/%.o) $(OBJS)
	$(CC) $(XCFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

unit-test: afreplay $(BUILD)/unit_tests
	./$(BUILD)/unit_tests

pcaps:
	python3 tests/gen_pcaps.py $(BUILD)/pcaps

func-test: afreplay pcaps
	tests/func_veth.sh $(BUILD)/pcaps

test: unit-test func-test

clean:
	rm -rf build build-san afreplay

# Проверочная сборка: UBSan в режиме trap (без рантайм-библиотеки) и FORTIFY.
# Если установлен libasan, можно добавить SAN=-fsanitize=address.
SAN ?=
sanitize:
	$(MAKE) BUILD=build-san CFLAGS="-O1 -g -fsanitize=undefined -fsanitize-trap=all \
		-D_FORTIFY_SOURCE=3 -fno-omit-frame-pointer $(SAN)" build-san/unit_tests
	./build-san/unit_tests

-include $(wildcard $(BUILD)/*.d $(BUILD)/tests/*.d)
