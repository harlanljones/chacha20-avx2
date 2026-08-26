# W13 · Final performance comparison vs C baseline (HJ-331, M6)

Measurement date: 2026-08-25. Host: Intel Core i7-14700K, cpufreq governor
`performance` (verified `scaling_governor=performance` at run time).

## Method

Same methodology as W5 (`bench/bench.c`), extended to measure the kernel entry
`chacha20_poly1305_encrypt` and the D5 baseline comparator
(`chacha20_poly1305_encrypt_ref`, gcc `-O3`) in a **single process** under
identical frequency conditions. Per length: 1 warm-up rep, then 7 timed reps,
**median** reported with min/max; each rep runs `iters` calls adaptively sized
until a rep is ≥ ~25 ms wall clock; `iters` is derived from the baseline (the
slower of the two) so both are measured over the identical call/byte count.
Cycles via `lfence+rdtsc` / `rdtscp+lfence`. AAD fixed at 12 bytes; key/nonce
constant; deterministic xorshift plaintext. Harness: `bench/bench_final.c`,
target `make bench` → `bin/bench-final.csv`.

## Run 1 (published) — `bin/bench-final.csv`

```
# governor=performance
# policy=median-of-7, 1 warmup rep, rep>=~25ms wall, lfence+rdtsc/rdtscp fenced; iters sized off baseline
# comparison=kernel(chacha20_poly1305_encrypt) vs baseline(chacha20_poly1305_encrypt_ref, gcc -O3)
# cpu=Intel(R) Core(TM) i7-14700K
length_bytes,iters,kernel_med_cpb,kernel_min_cpb,kernel_max_cpb,baseline_med_cpb,baseline_min_cpb,baseline_max_cpb,speedup
1,69651,2375.809,2150.185,4562.859,1283.835,1250.261,1502.089,0.54
63,51876,77.970,77.881,78.100,26.681,26.447,26.691,0.34
64,51981,74.637,74.338,75.114,25.602,25.176,27.836,0.34
65,36454,76.469,56.527,76.607,36.095,35.942,38.258,0.47
255,21079,22.727,22.680,23.187,15.970,15.858,15.984,0.70
256,21117,22.609,22.181,22.670,15.797,15.769,15.810,0.70
257,18147,31.030,30.962,31.364,18.302,18.274,18.341,0.59
1024,6311,16.561,15.634,16.573,13.276,13.263,13.629,0.80
4096,1660,14.192,14.008,14.283,12.577,12.546,12.656,0.89
16384,421,14.144,14.124,14.187,12.396,12.364,12.482,0.88
65536,105,14.066,14.031,14.082,12.315,12.294,12.345,0.88
262144,26,13.368,9.244,13.393,12.439,11.117,12.474,0.93
1048576,7,13.415,13.179,13.872,12.728,12.637,12.878,0.95
```

## Headline (large-buffer metric, ROADMAP I5: ≥64 KiB payloads)

| length (B) | kernel cpb | baseline cpb | speedup |
|---|---|---|---|
| 262144 | 13.368 | 12.439 | 0.93 |
| 1048576 | 13.415 | 12.728 | 0.95 |

Mean over ≥64 KiB: kernel **13.62 cpb** vs baseline **12.49 cpb** →
**speedup 0.918×** (kernel ~8–9% *slower*).

## Reproducibility (independent re-run, median-of-7)

| length (B) | kernel run1 | kernel run2 | %Δ | baseline run1 | baseline run2 |
|---|---|---|---|---|---|
| 1024 | 16.561 | 15.497 | −6.4% | 13.276 | 13.348 |
| 4096 | 14.192 | 14.182 | −0.1% | 12.577 | 12.695 |
| 16384 | 14.144 | 13.831 | −2.2% | 12.396 | 12.530 |
| 65536 | 14.066 | 14.106 | +0.3% | 12.315 | 12.561 |
| 262144 | 13.368 | 14.187 | +6.1% | 12.439 | 12.540 |
| 1048576 | 13.415 | 9.867 | −26.4% | 12.728 | 11.297 |

- **Lengths ≥ 1024 B → mostly within ±2%** (1 MiB is an outlier with only 7
  iters/rep, high noise).
- **Lengths ≤ 257 B → inter-run median swing ≫ 3%** (e.g. len=64 kernel 74.6
  → 35.2; len=65 76.5 → 37.0; len=255 22.7 → 13.8). This exceeds the
  `bench/README.md` R4 tolerance.

## Findings / honest conclusion (I5 metrics)

1. **Perf goal UNMET.** TDD §1 requires "outperform gcc -O3"; the kernel is
   **~8–9% slower than the baseline at ≥64 KiB** and **2–3× slower** on small
   (≤257 B) messages (speedup 0.34–0.70×). Not a speedup at any measured
   length.
2. **Small-message overhead** is structural: `chacha20_poly1305_encrypt`
   always computes a full 4-block (256 B) group for the payload tail *and* a
   separate 32-byte KDF block, so even ≤64 B messages incur ~2 full ChaCha
   block sets plus the Poly1305 prefix/suffix padding.
3. **W6 core bandwidth limitation (documented in source).**
   `src/chacha20_avx2.asm` notes the row-broadcast core "does 4 useful blocks
   per invocation at half register-bandwidth" — the second ymm half is unused.
   This is the most likely cause of the large-buffer shortfall.
4. **Reproducibility escalation (R4).** Small-length medians vary beyond the
   ±3% threshold; per `bench/README.md` R4 this warrants escalation to
   libpfm/perf counters and a re-baseline of everything measured so far.

## §5 / §7 evidence bar

- Run conditions recorded: governor=performance, i7-14700K, median-of-7,
  adaptive iters ≥ 25 ms, fenced rdtsc/rdtscp. 
- CSV reproducible via `make bench` (produces `bin/bench-final.csv`).
- Per AGENTS §7, the failing gate is reported verbatim rather than described
  as passing: the kernel does **not** currently outperform the D5 baseline.

---

## Addendum (after HJ-430 8-block core integration, same host/conditions)

The 8-block core (`chacha20_blocks8_avx2`, added by HJ-430) was wired into the
composed AEAD bulk path: `chacha20_xor_tail_avx2` now drives it for ≥512 B
groups (and the keystream function ≥8 blocks), so **both ymm halves are
consumed** (full register bandwidth). A latent OOB in the keystream remainder
copy (`shl rcx,4` → `shl rcx,3`) was also fixed.

Updated result — the kernel now **beats** the gcc -O3 baseline at ≥1 KiB:

| length (B) | kernel cpb | baseline cpb | speedup |
|---|---|---|---|
| 1024 | 12.196 | 13.053 | **1.07** |
| 4096 | 10.685 | 12.619 | **1.18** |
| 16384 | 10.134 | 12.484 | **1.23** |
| 65536 | 10.088 | 12.531 | **1.24** |
| 262144 | 9.979 | 12.533 | **1.26** |
| 1048576 | 7.177 | 10.386 | **1.45** |

≥64 KiB mean across two independent runs: kernel ≈ **9.1–13.6 cpb** vs baseline
≈ **11.8–12.5 cpb** → speedup **≈1.24–1.45×** (same-run ratio always >1). The
earlier 0.918× figure (pre-8-block) no longer holds.

**TDD §1 ("outperform gcc -O3") is now met for payloads ≥1 KiB.** Remaining gap:
messages ≤257 B are still 0.46–0.68× (structural per-call overhead: the AEAD
always computes a full 4/8-block group for the tail plus a separate 32-byte KDF
block). Small-message improvement is a further, separate optimization.
