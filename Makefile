# Toolchain (AGENTS.md §2 contract)
CC      := gcc
AS      := nasm

# Host ISA: avx2/bmi2/adx verified in /proc/cpuinfo (ROADMAP.md §1).
CFLAGS  := -O2 -Iinclude -mavx2 -mbmi2 -madx
ASFLAGS := -f elf64 -g -F dwarf

# Benchmark builds may use -O3 per AGENTS.md §2; the D5 baseline
# comparator (src/ref at -O3) is what those numbers must measure.
BENCH_CFLAGS := -O3 -Iinclude -mavx2 -mbmi2 -madx

C_SRCS   := $(wildcard src/*.c)
ASM_SRCS := $(wildcard src/*.asm)
REF_SRCS := $(wildcard src/ref/*.c)

OBJ     := $(ASM_SRCS:src/%.asm=obj/%.o) \
           $(C_SRCS:src/%.c=obj/%.o) \
           $(REF_SRCS:src/ref/%.c=obj/ref/%.o)

BENCH_REF_OBJ := $(REF_SRCS:src/ref/%.c=obj/bench-%.o)
BENCH_MAIN    := obj/bench-main.o
BENCH_BIN     := bin/bench-ref
BENCH_CSV     := bin/bench-ref.csv

TEST_BIN      := bin/test-vectors
TEST_REF_OBJ  := obj/ref/chacha20_ref.o obj/ref/poly1305_ref.o obj/ref/aead_ref.o
TEST_ABI_OBJ  := obj/test-abi_wrappers.o
TEST_ASM_OBJ  := obj/chacha20_avx2.o

BIN := bin

.PHONY: all test bench clean

all: $(OBJ)

obj/%.o: src/%.asm
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -o $@ $<

obj/%.o: src/%.c include/ref.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

obj/bench-%.o: src/ref/%.c include/ref.h
	@mkdir -p $(dir $@)
	$(CC) $(BENCH_CFLAGS) -c -o $@ $<

obj/bench-main.o: bench/bench.c include/ref.h
	@mkdir -p $(dir $@)
	$(CC) $(BENCH_CFLAGS) -Iinclude -c -o $@ $<

test: bin/test-vectors bin/abi-test bin/test-asm
	./bin/test-vectors && ./bin/abi-test && ./bin/test-asm

$(TEST_BIN): test/rfc8439_vectors.c test/rfc_vectors_data.h $(TEST_REF_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -o $@ test/rfc8439_vectors.c $(TEST_REF_OBJ)

bin/test-asm: test/chacha20_asm_vectors.c $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -Itest -o $@ test/chacha20_asm_vectors.c $(TEST_REF_OBJ) $(TEST_ASM_OBJ)

bin/abi-test: test/abi_test.c obj/test-abi_wrappers.o $(TEST_REF_OBJ) $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -no-pie -o $@ test/abi_test.c obj/test-abi_wrappers.o $(TEST_REF_OBJ) $(TEST_ASM_OBJ)

obj/test-abi_wrappers.o: test/abi_wrappers.asm
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -o $@ $<

bench: $(BENCH_BIN)
	@mkdir -p $(BIN)
	./$(BENCH_BIN) > $(BENCH_CSV)
	@echo "wrote $(BENCH_CSV)"

$(BENCH_BIN): $(BENCH_REF_OBJ) $(BENCH_MAIN) | $(BIN)
	$(CC) $(BENCH_CFLAGS) -o $@ $^

$(BIN):
	@mkdir -p $(BIN)

clean:
	rm -rf obj $(BIN)
