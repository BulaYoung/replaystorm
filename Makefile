# replaystorm — multithreaded pcap replayer over AF_PACKET
CC      ?= cc
CFLAGS  ?= -O2 -g
# Mandatory flags kept separate so that make CFLAGS=... does not drop them
XCFLAGS := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -pthread -MMD -MP
LDLIBS  += -pthread -lm

BUILD   := build
SRCS    := $(filter-out src/main.c,$(wildcard src/*.c))
OBJS    := $(SRCS:src/%.c=$(BUILD)/%.o)
TESTSRC := $(wildcard tests/test_*.c tests/ref_*.c)

.PHONY: all clean test unit-test func-test pcaps sanitize

all: replaystorm

replaystorm: $(OBJS) $(BUILD)/main.o
	$(CC) $(XCFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(XCFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD)/tests/%.o: tests/%.c | $(BUILD)
	@mkdir -p $(BUILD)/tests
	$(CC) $(XCFLAGS) $(CFLAGS) -iquote src -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/unit_tests: $(TESTSRC:tests/%.c=$(BUILD)/tests/%.o) $(OBJS)
	$(CC) $(XCFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

unit-test: replaystorm $(BUILD)/unit_tests
	./$(BUILD)/unit_tests

pcaps:
	python3 tests/gen_pcaps.py $(BUILD)/pcaps

func-test: replaystorm pcaps
	tests/func_veth.sh $(BUILD)/pcaps

test: unit-test func-test

clean:
	rm -rf build build-san replaystorm

# Checking build: UBSan in trap mode (no runtime library) and FORTIFY.
# If libasan is installed, SAN=-fsanitize=address can be added.
SAN ?=
sanitize:
	$(MAKE) BUILD=build-san CFLAGS="-O1 -g -fsanitize=undefined -fsanitize-trap=all \
		-D_FORTIFY_SOURCE=3 -fno-omit-frame-pointer $(SAN)" build-san/unit_tests
	./build-san/unit_tests

-include $(wildcard $(BUILD)/*.d $(BUILD)/tests/*.d)
