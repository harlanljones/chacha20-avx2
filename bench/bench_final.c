#include "ref.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Kernel entry point (exported from src/aead.asm; signature matches the
 * reference in include/ref.h). No header yet — declared here for the
 * benchmark harness. */
int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
                              const uint8_t *plaintext, size_t plaintext_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t nonce[12], const uint8_t key[32]);

/*
 * W13 final comparison harness (ticket HJ-331, M6).
 *
 * Measures, in a SINGLE process under identical frequency conditions,
 * the AVX2/BMI2 kernel entry `chacha20_poly1305_encrypt` against the
 * D5 baseline comparator (this repo's portable scalar C reference
 * built at -O3). Same methodology as W5 (bench.c): per length one
 * warmup rep, then REPS timed reps, median reported; each timed rep
 * runs `iters` calls, adaptively sized so a rep is >= ~25 ms wall.
 *
 * `iters` is derived from the *baseline* (the slower of the two), so
 * both implementations are measured over the identical iteration count
 * and byte count, giving a directly comparable cycles/byte.
 *
 * Output: CSV on stdout, one row per length:
 *   length_bytes,iters,kernel_med_cpb,kernel_min_cpb,kernel_max_cpb,
 *   baseline_med_cpb,baseline_min_cpb,baseline_max_cpb,speedup
 * preceded by `#` meta lines (date, CPU, cpufreq governor, policy).
 */

#define REPS          7
#define MIN_REP_MS    25
#define MAXLEN        (1024u * 1024u)

static const size_t kLengths[] = {
    1, 63, 64, 65, 255, 256, 257,
    1024, 4096, 16384, 65536, 262144, 1048576
};
#define NLENGTHS (sizeof(kLengths) / sizeof(kLengths[0]))

static volatile uint64_t g_sink;

static inline uint64_t tick_start(void)
{
    unsigned lo, hi;
    __asm__ volatile ("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t tick_stop(void)
{
    unsigned lo, hi;
    __asm__ volatile ("rdtscp" : "=a"(lo), "=d"(hi) :: "rcx", "memory");
    __asm__ volatile ("lfence" ::: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void fill_pattern(uint8_t *buf, size_t n)
{
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        buf[i] = (uint8_t)x;
    }
}

static int read_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(out, (int)cap, f)) {
        fclose(f);
        return -1;
    }
    out[strcspn(out, "\n")] = '\0';
    fclose(f);
    return 0;
}

static double median_cpb(uint64_t *cyc, size_t iters, size_t len)
{
    return (double)cyc[REPS / 2] / ((double)iters * (double)len);
}

int main(void)
{
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    };
    static const uint8_t aad[12] = {0};   /* aad_len fixed at 12 for matrix */

    uint8_t *pt = malloc(MAXLEN);
    uint8_t *ct = malloc(MAXLEN);
    uint8_t tag[16];
    uint64_t kcyc[REPS], bcyc[REPS];
    size_t li, i;
    char gov[64], model[128];

    if (!pt || !ct)
        return 1;
    fill_pattern(pt, MAXLEN);

    printf("# generator=bin/bench-final (W13)\n");
    printf("# date=%ld\n", (long)time(NULL));
    if (read_line("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                  gov, sizeof gov) == 0)
        printf("# governor=%s\n", gov);
    else
        printf("# governor=unknown\n");
    printf("# policy=median-of-%d, 1 warmup rep, rep>=~%dms wall, "
           "lfence+rdtsc/rdtscp fenced; iters sized off baseline\n",
           REPS, MIN_REP_MS);
    printf("# comparison=kernel(chacha20_poly1305_encrypt) vs "
           "baseline(chacha20_poly1305_encrypt_ref, gcc -O3)\n");

    {
        FILE *f = fopen("/proc/cpuinfo", "r");
        model[0] = '\0';
        if (f) {
            char line[256];
            while (fgets(line, sizeof line, f))
                if (!strncmp(line, "model name", 10)) {
                    char *v = strchr(line, ':');
                    if (v) {
                        v += 2;
                        v[strcspn(v, "\n")] = '\0';
                        snprintf(model, sizeof model, "%s", v);
                    }
                    break;
                }
            fclose(f);
        }
        printf("# cpu=%s\n", model);
    }

    printf("length_bytes,iters,kernel_med_cpb,kernel_min_cpb,kernel_max_cpb,"
           "baseline_med_cpb,baseline_min_cpb,baseline_max_cpb,speedup\n");

    for (li = 0; li < NLENGTHS; li++) {
        size_t len = kLengths[li];
        size_t iters = 1;

        /* warm-up + adaptive sizing (off baseline) to ~MIN_REP_MS per rep */
        do {
            double t0 = now_ms();
            for (i = 0; i < iters; i++)
                chacha20_poly1305_encrypt_ref(ct, tag, pt, len,
                                              aad, sizeof aad, nonce, key);
            g_sink ^= tag[0] ^ ct[len ? len - 1 : 0];
            double ms = now_ms() - t0;
            if (ms >= MIN_REP_MS || iters >= (1u << 22))
                break;
            iters = ms > 1.0 ? (size_t)(iters * MIN_REP_MS / ms)
                             : iters * 2 + 1;
            if (iters < 1)
                iters = 1;
        } while (1);

        for (i = 0; i < REPS; i++) {
            uint64_t c0, c1;
            size_t k;

            c0 = tick_start();
            for (k = 0; k < iters; k++)
                chacha20_poly1305_encrypt(ct, tag, pt, len,
                                          aad, sizeof aad, nonce, key);
            c1 = tick_stop();
            g_sink ^= tag[0] ^ ct[len ? len - 1 : 0];
            kcyc[i] = c1 - c0;

            c0 = tick_start();
            for (k = 0; k < iters; k++)
                chacha20_poly1305_encrypt_ref(ct, tag, pt, len,
                                              aad, sizeof aad, nonce, key);
            c1 = tick_stop();
            g_sink ^= tag[0] ^ ct[len ? len - 1 : 0];
            bcyc[i] = c1 - c0;
        }

        qsort(kcyc, REPS, sizeof kcyc[0], cmp_u64);
        qsort(bcyc, REPS, sizeof bcyc[0], cmp_u64);

        {
            double kmed = median_cpb(kcyc, iters, len);
            double bmed = median_cpb(bcyc, iters, len);
            double kmin = (double)kcyc[0] / ((double)iters * (double)len);
            double kmax = (double)kcyc[REPS - 1] / ((double)iters * (double)len);
            double bmin = (double)bcyc[0] / ((double)iters * (double)len);
            double bmax = (double)bcyc[REPS - 1] / ((double)iters * (double)len);
            printf("%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.2f\n",
                   len, iters, kmed, kmin, kmax, bmed, bmin, bmax,
                   bmed / kmed);
        }
    }

    free(pt);
    free(ct);
    return (int)(g_sink & 0);
}
