#include "sha_benchmark.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "esp_timer.h"
#include "esp_random.h"
#include "soc/soc_caps.h"
#include "sha/sha_core.h"

#include "mbedtls/sha512.h"

#define MAX_INPUT_LEN 16384

static const size_t k_lengths[] = {32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(esp_random() & 0xFF);
    }
}

static double measure_sha256_us(const uint8_t *buf, size_t len, size_t iterations) {
    uint8_t out[32];
    uint64_t total = 0;

    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = esp_timer_get_time();
        esp_sha(SHA2_256, buf, len, out);
        uint64_t end = esp_timer_get_time();
        total += (end - start);
    }

    (void)out[0];
    return (iterations > 0) ? ((double)total / (double)iterations) : 0.0;
}

static double measure_full_domain_us(const uint8_t *buf, size_t len, size_t hashes, size_t iterations) {
#if !SOC_SHA_SUPPORT_SHA512
    (void)buf; (void)len; (void)hashes; (void)iterations;
    return -1.0;
#else
    uint8_t out[64 * 8];
    uint64_t total = 0;

    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = esp_timer_get_time();
        for (size_t k = 0; k < hashes; k++) {
            mbedtls_sha512_context ctx;
            mbedtls_sha512_init(&ctx);
            if (mbedtls_sha512_starts(&ctx, 0) != 0) {
                mbedtls_sha512_free(&ctx);
                return -1.0;
            }
            if (mbedtls_sha512_update(&ctx, buf, len) != 0) {
                mbedtls_sha512_free(&ctx);
                return -1.0;
            }
            uint8_t ctr = (uint8_t)k;
            if (mbedtls_sha512_update(&ctx, &ctr, 1) != 0) {
                mbedtls_sha512_free(&ctx);
                return -1.0;
            }
            if (mbedtls_sha512_finish(&ctx, out + (k * 64)) != 0) {
                mbedtls_sha512_free(&ctx);
                return -1.0;
            }
            mbedtls_sha512_free(&ctx);
        }
        uint64_t end = esp_timer_get_time();
        total += (end - start);
    }

    (void)out[0];
    return (iterations > 0) ? ((double)total / (double)iterations) : 0.0;
#endif
}

void benchmark_sha256_lengths(size_t iterations) {
    printf("\n══════════════════════════════════════════\n");
    printf("SHA256 Hardware Benchmark (setup + per-byte)\n");
    printf("Lengths: 32..16384 bytes\n");
    printf("Iterations: %zu\n", iterations);
    printf("══════════════════════════════════════════\n");

    uint8_t *buf = (uint8_t *)malloc(MAX_INPUT_LEN);
    if (!buf) {
        printf("Memory allocation failed\n");
        return;
    }
    fill_random(buf, MAX_INPUT_LEN);

    double setup_us = measure_sha256_us(buf, 0, iterations);

    printf("CSV_SHA256_HEADER,len,total_us,setup_us,per_byte_us\n");
    printf("SHA256 setup (len=0): %.2f us\n", setup_us);

    for (size_t i = 0; i < sizeof(k_lengths) / sizeof(k_lengths[0]); i++) {
        size_t len = k_lengths[i];
        double total_us = measure_sha256_us(buf, len, iterations);
        double per_byte = 0.0;
        if (len > 0 && total_us > setup_us) {
            per_byte = (total_us - setup_us) / (double)len;
        }
        printf("CSV_SHA256,%zu,%.2f,%.2f,%.6f\n", len, total_us, setup_us, per_byte);
    }

    free(buf);
}

void benchmark_full_domain_hash(size_t output_bits, size_t iterations) {
    size_t hashes = 0;
    if (output_bits == 2048) {
        hashes = 4;
    } else if (output_bits == 4096) {
        hashes = 8;
    } else {
        printf("Unsupported full-domain output size: %zu bits\n", output_bits);
        return;
    }

#if !SOC_SHA_SUPPORT_SHA512
    printf("SHA512 hardware not supported on this target.\n");
    return;
#endif

    printf("\n══════════════════════════════════════════\n");
    printf("Full-Domain Hash Benchmark (SHA512 x%zu)\n", hashes);
    printf("Output: %zu bits\n", output_bits);
    printf("Lengths: 32..16384 bytes\n");
    printf("Iterations: %zu\n", iterations);
    printf("══════════════════════════════════════════\n");

    uint8_t *buf = (uint8_t *)malloc(MAX_INPUT_LEN);
    if (!buf) {
        printf("Memory allocation failed\n");
        return;
    }
    fill_random(buf, MAX_INPUT_LEN);

    double setup_us = measure_full_domain_us(buf, 0, hashes, iterations);
    if (setup_us < 0.0) {
        printf("Full-domain hash measurement failed\n");
        free(buf);
        return;
    }

    printf("CSV_FDH_HEADER,output_bits,len,total_us,setup_us,per_byte_us,bytes_processed\n");
    printf("FDH setup (len=0, %zu hashes): %.2f us\n", hashes, setup_us);

    for (size_t i = 0; i < sizeof(k_lengths) / sizeof(k_lengths[0]); i++) {
        size_t len = k_lengths[i];
        double total_us = measure_full_domain_us(buf, len, hashes, iterations);
        double per_byte = 0.0;
        size_t bytes_processed = hashes * (len + 1); // +1 counter byte per hash
        if (bytes_processed > 0 && total_us > setup_us) {
            per_byte = (total_us - setup_us) / (double)bytes_processed;
        }
        printf("CSV_FDH,%zu,%zu,%.2f,%.2f,%.6f,%zu\n",
               output_bits, len, total_us, setup_us, per_byte, bytes_processed);
    }

    free(buf);
}
