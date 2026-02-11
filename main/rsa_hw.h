#ifndef RSA_HW_H
#define RSA_HW_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "soc/hwcrypto_reg.h"
#include "mbedtls/bignum.h"

// 4096-bit configuration
#define RSA_4096_BITS 4096
#define RSA_4096_BYTES (RSA_4096_BITS / 8)
#define RSA_4096_WORDS (RSA_4096_BITS / 32)  // 128 words

// ==================== WORKING FUNCTIONS ====================
void generate_random_4096_odd(uint32_t *num);
void print_4096_sample(const char* label, const uint32_t *num);
bool is_zero_4096(const uint32_t *num);

// Memory access (TESTED AND WORKING)
bool test_memory_access(void);

// Hardware control (PARTIALLY WORKING)
void rsa_periph_enable(bool enable);
bool rsa_write_block(uint32_t block_addr, const uint32_t *data);
bool rsa_read_block(uint32_t block_addr, uint32_t *data);

// Hardware operation
bool rsa_mod_mult_hw(const uint32_t *X, const uint32_t *Y, 
                     const uint32_t *M, uint32_t *Z);
bool rsa_mod_exp_hw(const uint32_t *X, const uint32_t *E,
                    const uint32_t *M, uint32_t *Z);
bool verify_hw_sw_small_mult(size_t iterations);
bool verify_hw_sw_small_exp(size_t iterations);

typedef struct {
    size_t words;
    size_t hw_words;
    uint32_t mprime;
    mbedtls_mpi M;
    mbedtls_mpi Rinv;
} rsa_mont_ctx_t;

bool rsa_mont_ctx_init(rsa_mont_ctx_t *ctx, const uint32_t *M_words, size_t words);
void rsa_mont_ctx_free(rsa_mont_ctx_t *ctx);

bool rsa_mpi_set_words(mbedtls_mpi *X, const uint32_t *words, size_t n_words);
void rsa_mpi_get_words(const mbedtls_mpi *X, uint32_t *words, size_t n_words);

bool rsa_mod_mult_hw_ctx(const rsa_mont_ctx_t *ctx,
                         const mbedtls_mpi *X, const mbedtls_mpi *Y,
                         mbedtls_mpi *Z);
bool rsa_mod_exp_hw_ctx(const rsa_mont_ctx_t *ctx,
                        const mbedtls_mpi *X, const mbedtls_mpi *E,
                        mbedtls_mpi *Z, bool feed_wdt);

// Debug functions
void print_rsa_registers(const char* label);
void debug_simple_hardware_test(void);

// Benchmarks
void benchmark_suite_fixed_mod(size_t bits, size_t iter_mult, size_t iter_exp_small, size_t iter_exp_full);

#endif // RSA_HW_H_HW_H
