#include "rsa_hw.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_random.h"

#define RSA_2048_BITS 2048
#define RSA_2048_WORDS (RSA_2048_BITS / 32)

// ==================== BENCHMARK FUNCTIONS ====================

typedef struct {
    uint64_t min_us;
    uint64_t max_us;
    uint64_t total_us;
    double sumsq;
    size_t count;
} bench_stats_t;

static void stats_init(bench_stats_t *s) {
    s->min_us = UINT64_MAX;
    s->max_us = 0;
    s->total_us = 0;
    s->sumsq = 0.0;
    s->count = 0;
}

static void stats_update(bench_stats_t *s, uint64_t us) {
    if (us < s->min_us) s->min_us = us;
    if (us > s->max_us) s->max_us = us;
    s->total_us += us;
    s->sumsq += (double)us * (double)us;
    s->count++;
}

static double stats_avg_us(const bench_stats_t *s) {
    if (s->count == 0) return 0.0;
    return (double)s->total_us / (double)s->count;
}

static double stats_stddev_us(const bench_stats_t *s) {
    if (s->count == 0) return 0.0;
    double mean = stats_avg_us(s);
    double var = (s->sumsq / (double)s->count) - (mean * mean);
    return (var > 0.0) ? sqrt(var) : 0.0;
}

static void csv_iter(const char *op, size_t bits, const char *exp_label, size_t iter, uint64_t us) {
    printf("CSV,%s,%zu,%s,%zu,%" PRIu64 "\n", op, bits, exp_label, iter, us);
}

static void csv_summary(const char *op, size_t bits, const char *exp_label,
                        size_t iterations, size_t success, const bench_stats_t *s) {
    double avg = stats_avg_us(s);
    double stddev = stats_stddev_us(s);
    printf("CSV_SUMMARY,%s,%zu,%s,%zu,%zu,%.2f,%" PRIu64 ",%" PRIu64 ",%.2f\n",
           op, bits, exp_label, iterations, success, avg, s->min_us, s->max_us, stddev);
}

static void fill_random_words(uint32_t *num, size_t words) {
    uint8_t *bytes = (uint8_t *)num;
    for (size_t i = 0; i < words * 4; i++) {
        bytes[i] = esp_random() & 0xFF;
    }
}

static void set_msb(uint32_t *num, size_t bits) {
    size_t last = (bits / 32) - 1;
    num[last] |= 0x80000000u;
}

static void clear_msb(uint32_t *num, size_t bits) {
    size_t last = (bits / 32) - 1;
    num[last] &= 0x7FFFFFFFu;
}

static void generate_modulus(uint32_t *M, size_t bits) {
    size_t words = bits / 32;
    fill_random_words(M, words);
    set_msb(M, bits);
    M[0] |= 0x01u; // ensure odd
}

static void generate_operand(uint32_t *X, size_t bits) {
    size_t words = bits / 32;
    fill_random_words(X, words);
    clear_msb(X, bits); // ensure < modulus with MSB set
}

static uint32_t choose_small_exponent(uint32_t *factors, size_t *factor_count) {
    const uint32_t primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29};
    const size_t primes_count = sizeof(primes) / sizeof(primes[0]);
    const uint32_t target = 20000;

    uint32_t best = 0;
    uint32_t best_diff = UINT32_MAX;
    uint32_t best_factors[5] = {0};
    size_t best_count = 0;

    for (uint32_t mask = 1; mask < (1u << primes_count); mask++) {
        size_t count = 0;
        uint64_t prod = 1;
        for (size_t i = 0; i < primes_count; i++) {
            if (mask & (1u << i)) {
                count++;
                if (count > 5) {
                    break;
                }
                prod *= primes[i];
            }
        }
        if (count == 0 || count > 5) {
            continue;
        }
        if (prod > UINT32_MAX) {
            continue;
        }
        uint32_t p = (uint32_t)prod;
        uint32_t diff = (p > target) ? (p - target) : (target - p);
        if (diff < best_diff) {
            best_diff = diff;
            best = p;
            best_count = count;
            size_t idx = 0;
            for (size_t i = 0; i < primes_count; i++) {
                if (mask & (1u << i)) {
                    best_factors[idx++] = primes[i];
                }
            }
        }
    }

    if (factors && factor_count) {
        for (size_t i = 0; i < best_count; i++) {
            factors[i] = best_factors[i];
        }
        *factor_count = best_count;
    }

    return best;
}

static void set_small_exponent(uint32_t *E, size_t words, uint32_t exp) {
    memset(E, 0, words * sizeof(uint32_t));
    E[0] = exp;
}

static void set_full_exponent(uint32_t *E, size_t bits) {
    size_t words = bits / 32;
    fill_random_words(E, words);
    set_msb(E, bits);
}

static void benchmark_modmult_ctx(const rsa_mont_ctx_t *ctx, size_t bits, size_t iterations) {
    size_t words = bits / 32;

    uint32_t *X = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);
    uint32_t *Y = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);
    uint32_t *Z = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);

    if (!X || !Y || !Z) {
        printf("Memory allocation failed\n");
        return;
    }

    mbedtls_mpi X_mpi, Y_mpi, Z_mpi;
    mbedtls_mpi_init(&X_mpi);
    mbedtls_mpi_init(&Y_mpi);
    mbedtls_mpi_init(&Z_mpi);

    const size_t warmup = 1;
    printf("\n══════════════════════════════════════════\n");
    printf("Modular Multiplication Benchmark (%zu-bit, fixed modulus)\n", bits);
    printf("Iterations: %zu\n", iterations);
    printf("Warm-up iterations: %zu\n", warmup);
    printf("══════════════════════════════════════════\n");

    for (size_t i = 0; i < warmup; i++) {
        generate_operand(X, bits);
        generate_operand(Y, bits);
        rsa_mpi_set_words(&X_mpi, X, words);
        rsa_mpi_set_words(&Y_mpi, Y, words);
        (void)rsa_mod_mult_hw_ctx(ctx, &X_mpi, &Y_mpi, &Z_mpi);
    }

    bench_stats_t stats;
    stats_init(&stats);
    size_t successful_ops = 0;

    printf("\nStarting benchmark...\n");

    for (size_t i = 0; i < iterations; i++) {
        generate_operand(X, bits);
        generate_operand(Y, bits);
        rsa_mpi_set_words(&X_mpi, X, words);
        rsa_mpi_set_words(&Y_mpi, Y, words);

        uint64_t start = esp_timer_get_time();
        bool success = rsa_mod_mult_hw_ctx(ctx, &X_mpi, &Y_mpi, &Z_mpi);
        uint64_t end = esp_timer_get_time();

        if (success) {
            uint64_t us = end - start;
            stats_update(&stats, us);
            successful_ops++;
            csv_iter("modmult", bits, "na", i + 1, us);

            if (iterations >= 5 && (i + 1) % (iterations / 5) == 0) {
                printf("  Progress: %zu/%zu\n", i + 1, iterations);
            }
        } else {
            printf("  Failed at iteration %zu\n", i);
            break;
        }
    }

    if (successful_ops > 0) {
        double avg_us = stats_avg_us(&stats);
        double stddev_us = stats_stddev_us(&stats);
        printf("\nBenchmark Results:\n");
        printf("  Successful operations: %zu/%zu\n", successful_ops, iterations);
        printf("  Total time: %" PRIu64 " µs\n", stats.total_us);
        printf("  Average time: %.2f µs\n", avg_us);
        printf("  Average time: %.2f ms\n", avg_us / 1000.0);
        printf("  Stddev: %.2f µs\n", stddev_us);
        printf("  Min: %" PRIu64 " µs\n", stats.min_us);
        printf("  Max: %" PRIu64 " µs\n", stats.max_us);

        rsa_mpi_get_words(&Z_mpi, Z, words);
        bool any_nonzero = false;
        for (size_t i = 0; i < words; i++) {
            if (Z[i] != 0) {
                any_nonzero = true;
                break;
            }
        }
        printf("  Result is %s\n", any_nonzero ? "non-zero ✓" : "zero ⚠");

        csv_summary("modmult", bits, "na", iterations, successful_ops, &stats);
    } else {
        printf("\nNo successful operations!\n");
    }

    mbedtls_mpi_free(&X_mpi);
    mbedtls_mpi_free(&Y_mpi);
    mbedtls_mpi_free(&Z_mpi);

    heap_caps_free(X);
    heap_caps_free(Y);
    heap_caps_free(Z);
}

static void benchmark_modexp_ctx(const rsa_mont_ctx_t *ctx, size_t bits, size_t iterations,
                                 const uint32_t *E_words, const char *exp_label, bool feed_wdt) {
    size_t words = bits / 32;

    uint32_t *X = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);
    uint32_t *Z = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);

    if (!X || !Z) {
        printf("Memory allocation failed\n");
        return;
    }

    mbedtls_mpi X_mpi, E_mpi, Z_mpi;
    mbedtls_mpi_init(&X_mpi);
    mbedtls_mpi_init(&E_mpi);
    mbedtls_mpi_init(&Z_mpi);

    rsa_mpi_set_words(&E_mpi, E_words, words);

    const size_t warmup = 1;
    printf("\n══════════════════════════════════════════\n");
    printf("Modular Exponentiation Benchmark (%zu-bit, %s exponent, fixed modulus)\n", bits, exp_label);
    printf("Iterations: %zu\n", iterations);
    printf("Warm-up iterations: %zu\n", warmup);
    printf("══════════════════════════════════════════\n");

    for (size_t i = 0; i < warmup; i++) {
        generate_operand(X, bits);
        rsa_mpi_set_words(&X_mpi, X, words);
        (void)rsa_mod_exp_hw_ctx(ctx, &X_mpi, &E_mpi, &Z_mpi, feed_wdt);
    }

    bench_stats_t stats;
    stats_init(&stats);
    size_t successful_ops = 0;

    printf("\nStarting benchmark...\n");

    for (size_t i = 0; i < iterations; i++) {
        generate_operand(X, bits);
        rsa_mpi_set_words(&X_mpi, X, words);

        uint64_t start = esp_timer_get_time();
        bool success = rsa_mod_exp_hw_ctx(ctx, &X_mpi, &E_mpi, &Z_mpi, feed_wdt);
        uint64_t end = esp_timer_get_time();

        if (success) {
            uint64_t us = end - start;
            stats_update(&stats, us);
            successful_ops++;
            csv_iter("modexp", bits, exp_label, i + 1, us);

            if (iterations >= 5 && (i + 1) % (iterations / 5) == 0) {
                printf("  Progress: %zu/%zu\n", i + 1, iterations);
            }
        } else {
            printf("  Failed at iteration %zu\n", i);
            break;
        }
    }

    if (successful_ops > 0) {
        double avg_us = stats_avg_us(&stats);
        double stddev_us = stats_stddev_us(&stats);
        printf("\nBenchmark Results:\n");
        printf("  Successful operations: %zu/%zu\n", successful_ops, iterations);
        printf("  Total time: %" PRIu64 " µs\n", stats.total_us);
        printf("  Average time: %.2f µs\n", avg_us);
        printf("  Average time: %.2f ms\n", avg_us / 1000.0);
        printf("  Stddev: %.2f µs\n", stddev_us);
        printf("  Min: %" PRIu64 " µs\n", stats.min_us);
        printf("  Max: %" PRIu64 " µs\n", stats.max_us);

        rsa_mpi_get_words(&Z_mpi, Z, words);
        bool any_nonzero = false;
        for (size_t i = 0; i < words; i++) {
            if (Z[i] != 0) {
                any_nonzero = true;
                break;
            }
        }
        printf("  Result is %s\n", any_nonzero ? "non-zero ✓" : "zero ⚠");

        csv_summary("modexp", bits, exp_label, iterations, successful_ops, &stats);
    } else {
        printf("\nNo successful operations!\n");
    }

    mbedtls_mpi_free(&X_mpi);
    mbedtls_mpi_free(&E_mpi);
    mbedtls_mpi_free(&Z_mpi);

    heap_caps_free(X);
    heap_caps_free(Z);
}

void benchmark_suite_fixed_mod(size_t bits, size_t iter_mult, size_t iter_exp_small, size_t iter_exp_full) {
    size_t words = bits / 32;

    uint32_t *M = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);
    uint32_t *E_small = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);
    uint32_t *E_full = heap_caps_calloc(words, sizeof(uint32_t), MALLOC_CAP_DEFAULT);

    if (!M || !E_small || !E_full) {
        printf("Memory allocation failed\n");
        return;
    }

    generate_modulus(M, bits);

    printf("\n══════════════════════════════════════════\n");
    printf("Fixed Modulus Setup (%zu-bit)\n", bits);
    printf("M: [0x%08" PRIX32 " ... 0x%08" PRIX32 "]\n", M[words - 1], M[0]);
    printf("══════════════════════════════════════════\n");

    rsa_mont_ctx_t ctx;
    if (!rsa_mont_ctx_init(&ctx, M, words)) {
        printf("Failed to initialize Montgomery context\n");
        heap_caps_free(M);
        heap_caps_free(E_small);
        heap_caps_free(E_full);
        return;
    }

    uint32_t factors[5] = {0};
    size_t factor_count = 0;
    uint32_t small_exp = choose_small_exponent(factors, &factor_count);
    set_small_exponent(E_small, words, small_exp);
    set_full_exponent(E_full, bits);

    printf("Small exponent target ~20000, chosen: %" PRIu32 " (product of %zu primes)\n", small_exp, factor_count);
    if (factor_count > 0) {
        printf("  Primes: ");
        for (size_t i = 0; i < factor_count; i++) {
            printf("%" PRIu32 "%s", factors[i], (i + 1 < factor_count) ? "*" : "\n");
        }
    }

    printf("Full-domain exponent: %zu-bit random value\n", bits);

    benchmark_modmult_ctx(&ctx, bits, iter_mult);
    benchmark_modexp_ctx(&ctx, bits, iter_exp_small, E_small, "small", false);

    if (iter_exp_full > 0) {
        printf("Note: full-domain exponent timing can be very slow for %zu-bit.\n", bits);
        benchmark_modexp_ctx(&ctx, bits, iter_exp_full, E_full, "full", true);
    }

    rsa_mont_ctx_free(&ctx);

    heap_caps_free(M);
    heap_caps_free(E_small);
    heap_caps_free(E_full);
}
