# chacha20-avx2

Standalone RFC 8439 ChaCha20-Poly1305 AEAD kernel in hand-tuned x86-64 NASM
assembly (AVX2 4-block-interleave ChaCha20, BMI2/ADX Poly1305 planned), exposed
through a System V AMD64 C-compatible entry point. Constant-time by
construction; differential-validated against libsodium/OpenSSL oracles;
benchmarked against the in-repo gcc -O3 C reference.

## Layout

```
include/ref.h          reference API (oracle + baseline comparator)
src/ref/               portable scalar C reference (correctness oracle)
src/chacha20_avx2.asm  AVX2 4-block ChaCha20 core + keystream driver
test/                  RFC 8439 vector suite, ABI conformance probes,
                       asm validation suite
bench/                 rdtsc/rdtscp benchmark harness + methodology docs
docs/agents/           agent process config (tracker, labels, domain rules)
TDD.md                 technical design (authoritative)
ROADMAP.md             execution plan: milestones, work items, gates
AGENTS.md              process rules for development agents
```

## Build & test

```sh
make all      # kernel objects + harness objects
make test     # RFC 8439 vectors · ABI conformance · asm validation
make bench    # cycles/byte CSV -> bin/bench-ref.csv (see bench/README.md)
make clean
```

Toolchain: gcc, make, nasm (3.x verified). Host must expose `avx2`, `bmi2`,
`adx`. Benchmark numbers are only meaningful with the CPU governor pinned to
`performance`.

## Current status

Tracked ticket-by-ticket in Linear (`chacha20-avx2` project); milestones and
verified state live in `ROADMAP.md` §1/§6. Suites at last update:
24/24 RFC vectors · 11/11 ABI checks · 13/13 asm checks.

ChaCha20 AVX2 core validated (D6/R8 closed). Poly1305 engine (W8) gated on
the radix decision; composition, fuzzing, and final perf comparison follow.
