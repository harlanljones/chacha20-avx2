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

BENCH_FINAL_MAIN := obj/bench-final-main.o
BENCH_FINAL_BIN  := bin/bench-final
BENCH_FINAL_CSV  := bin/bench-final.csv

TEST_BIN      := bin/test-vectors
TEST_REF_OBJ  := obj/ref/chacha20_ref.o obj/ref/poly1305_ref.o obj/ref/aead_ref.o
TEST_ABI_OBJ  := obj/test-abi_wrappers.o
TEST_ASM_OBJ  := $(ASM_SRCS:src/%.asm=obj/%.o)

# HJ-329: differential fuzz harness (libsodium oracle + clang/libFuzzer).
# Separate from `make test`: it needs libsodium + clang at BUILD time only,
# so it never derives a runtime dependency for the shipped kernel. The kernel
# asm objects are the same ones built by nasm above; only the harness + oracle
# .c are compiled by clang.
FUZZ_CC         := clang
FUZZ_CFLAGS     := -fsanitize=fuzzer,address,undefined -g -O1 \
                   -fno-omit-frame-pointer -Iinclude -Ioracle \
                   -mavx2 -mbmi2 -madx
FUZZ_OBJ_CFLAGS := -fsanitize=address,undefined -g -O1 \
                   -fno-omit-frame-pointer -Iinclude -Ioracle \
                   -mavx2 -mbmi2 -madx
FUZZ_LIBS       := $(shell pkg-config --libs libsodium)
FUZZ_ORACLE_OBJ := obj/oracle/aead_oracle.o
FUZZ_ASM_OBJ    := $(ASM_SRCS:src/%.asm=obj/%.o)
FUZZ_BIN        := bin/fuzz-aead
CHECK_DIFF_BIN  := bin/check-diff

BIN := bin

.PHONY: all test bench clean fuzz fuzz-aead check-diff

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

obj/bench-final-main.o: bench/bench_final.c include/ref.h
	@mkdir -p $(dir $@)
	$(CC) $(BENCH_CFLAGS) -Iinclude -c -o $@ $<

test: bin/test-vectors bin/abi-test bin/test-asm bin/test-poly-bmi2 bin/test-aead
	./bin/test-vectors && ./bin/abi-test && ./bin/test-asm && ./bin/test-poly-bmi2 && ./bin/test-aead

$(TEST_BIN): test/rfc8439_vectors.c test/rfc_vectors_data.h $(TEST_REF_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -o $@ test/rfc8439_vectors.c $(TEST_REF_OBJ)

bin/test-asm: test/chacha20_asm_vectors.c $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -Itest -o $@ test/chacha20_asm_vectors.c $(TEST_REF_OBJ) $(TEST_ASM_OBJ)

bin/test-poly-bmi2: test/poly1305_bmi2_vectors.c $(TEST_REF_OBJ) $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -Itest -o $@ test/poly1305_bmi2_vectors.c $(TEST_REF_OBJ) $(TEST_ASM_OBJ)

bin/abi-test: test/abi_test.c obj/test-abi_wrappers.o $(TEST_REF_OBJ) $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -no-pie -o $@ test/abi_test.c obj/test-abi_wrappers.o $(TEST_REF_OBJ) $(TEST_ASM_OBJ)

bin/test-aead: test/aead_asm_vectors.c $(TEST_REF_OBJ) $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(CFLAGS) -Itest -o $@ test/aead_asm_vectors.c $(TEST_REF_OBJ) $(TEST_ASM_OBJ)

obj/test-abi_wrappers.o: test/abi_wrappers.asm
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -o $@ $<

bench: $(BENCH_BIN) $(BENCH_FINAL_BIN)
	@mkdir -p $(BIN)
	./$(BENCH_BIN) > $(BENCH_CSV)
	@echo "wrote $(BENCH_CSV)"
	./$(BENCH_FINAL_BIN) > $(BENCH_FINAL_CSV)
	@echo "wrote $(BENCH_FINAL_CSV)"

$(BENCH_BIN): $(BENCH_REF_OBJ) $(BENCH_MAIN) | $(BIN)
	$(CC) $(BENCH_CFLAGS) -o $@ $^

$(BENCH_FINAL_BIN): $(BENCH_REF_OBJ) $(BENCH_FINAL_MAIN) $(TEST_ASM_OBJ) | $(BIN)
	$(CC) $(BENCH_CFLAGS) -o $@ $^

$(BIN):
	@mkdir -p $(BIN)

# --- HJ-329 fuzz harness rules -------------------------------------------
# Oracle adapter is compiled without -fsanitize=fuzzer (it has no
# LLVMFuzzerTestOneInput); only the fuzz target file is compiled/linked with
# -fsanitize=fuzzer so clang supplies the libFuzzer driver main().
obj/oracle/%.o: oracle/%.c oracle/aead_oracle.h
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_OBJ_CFLAGS) -c -o $@ $<

$(FUZZ_BIN): fuzz/fuzz_aead.c $(FUZZ_ORACLE_OBJ) $(FUZZ_ASM_OBJ) | $(BIN)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_aead.c $(FUZZ_ORACLE_OBJ) $(FUZZ_ASM_OBJ) $(FUZZ_LIBS)

$(CHECK_DIFF_BIN): fuzz/check_diff_fixed.c $(FUZZ_ORACLE_OBJ) $(FUZZ_ASM_OBJ) | $(BIN)
	$(FUZZ_CC) $(FUZZ_OBJ_CFLAGS) -o $@ fuzz/check_diff_fixed.c $(FUZZ_ORACLE_OBJ) $(FUZZ_ASM_OBJ) $(FUZZ_LIBS)

fuzz: $(FUZZ_BIN)
fuzz-aead: $(FUZZ_BIN)
check-diff: $(CHECK_DIFF_BIN)

clean:
	rm -rf obj $(BIN)
