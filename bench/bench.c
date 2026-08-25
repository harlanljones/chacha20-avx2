#include "ref.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * W5 baseline benchmark harness (decision D5: comparator = this repo's
 * portable scalar C reference built at -O3).
 *
 * Methodology (see bench/README.md):
 *   - per length: 1 warm-up rep, then REPS timed reps, report median
 *   - each rep adaptively sized to run >= ~25 ms wall clock
 *   - cycles via lfence+rdtsc (start) and rdtscp+lfence (stop)
 *   - deterministic inputs; results written as CSV to stdout
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
    uint64_t cyc[REPS];
    size_t li, i;
    char gov[64], model[128];

    if (!pt || !ct)
        return 1;
    fill_pattern(pt, MAXLEN);

    printf("# generator=bin/bench-ref (W5)\n");
    printf("# date=%ld\n", (long)time(NULL));
    if (read_line("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                  gov, sizeof gov) == 0)
        printf("# governor=%s\n", gov);
    else
        printf("# governor=unknown\n");
    printf("# policy=median-of-%d, 1 warmup rep, rep>=~%dms wall, "
           "lfence+rdtsc/rdtscp fenced\n", REPS, MIN_REP_MS);
    printf("# note=governor/frequency pinning may require sudo; see bench/README.md\n");

    /* CPU model line from /proc/cpuinfo */
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

    printf("length_bytes,iters,median_cycles_per_byte,min_cpb,max_cpb\n");

    for (li = 0; li < NLENGTHS; li++) {
        size_t len = kLengths[li];
        size_t iters = 1;

        /* warm-up + adaptive sizing to ~MIN_REP_MS wall per rep */
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
            uint64_t c0 = tick_start();
            size_t k;
            for (k = 0; k < iters; k++)
                chacha20_poly1305_encrypt_ref(ct, tag, pt, len,
                                              aad, sizeof aad, nonce, key);
            uint64_t c1 = tick_stop();
            g_sink ^= tag[0] ^ ct[len ? len - 1 : 0];
            cyc[i] = (c1 - c0);
        }

        qsort(cyc, REPS, sizeof cyc[0], cmp_u64);
        {
            double med_cpb = (double)cyc[REPS / 2] /
                             ((double)iters * (double)len);
            double min_cpb = (double)cyc[0] / ((double)iters * (double)len);
            double max_cpb = (double)cyc[REPS - 1] /
                             ((double)iters * (double)len);
            printf("%zu,%zu,%.3f,%.3f,%.3f\n",
                   len, iters, med_cpb, min_cpb, max_cpb);
        }
    }

    free(pt);
    free(ct);
    return (int)(g_sink & 0);  /* keep sink live without affecting exit */
}
