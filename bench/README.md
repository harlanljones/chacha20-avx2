# Benchmark methodology (W5)

Baseline comparator (decision **D5**, ratified): this repo's portable scalar
C reference in `src/ref/`, built with gcc at **-O3** plus the host ISA flags.
libsodium / OpenSSL are correctness oracles only, never performance baselines.

## How `make bench` measures

1. Payload-length matrix (bytes): 1, 63, 64, 65, 255, 256, 257, 1024, 4096,
   16384, 65536, 262144, 1048576. AAD fixed at 12 bytes; key/nonce constant
   across runs; plaintext is a deterministic xorshift pattern.
2. Per length: one warm-up repetition, then the harness adaptively grows the
   per-rep iteration count until one rep takes ≥ ~25 ms wall clock, so timer
   overhead is noise, not signal.
3. 7 timed repetitions per length. Cycles read via `lfence + rdtsc` (start)
   and `rdtscp + lfence` (stop). The **median** of 7 is reported alongside
   min/max so variance is visible instead of hidden.
4. Output: CSV on stdout (`length_bytes,iters,median_cycles_per_byte,min_cpb,
   max_cpb`) preceded by `#` meta lines (date, CPU model, cpufreq governor,
   policy). `make bench` writes it to `bin/bench-ref.csv`.

## Frequency handling (ROADMAP R4)

The harness records the current `scaling_governor` in the CSV header but does
not change system state. For comparable numbers across days:

```sh
sudo cpupower frequency-set -g performance   # human-run; needs sudo
```

Verify with `cpupower frequency-info | grep governor`. If medians for identical
runs vary beyond ±3%, escalate: switch to libpfm/perf counters and re-baseline
everything measured so far (R4 mitigation).

## Reproducing a number

```sh
make bench && cat bin/bench-ref.csv
```

A claim is reproducible when an independent re-run's median falls within the
stated variance of the published figure (AGENTS.md §5).
