#include "rsa_hw.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/dport_reg.h"
#include "bignum_impl.h"
#include "hal/mpi_hal.h"

// ==================== WORKING FUNCTIONS ====================

static uint32_t montmul_init_u32(const uint32_t *n) {
    uint32_t x = n[0];
    x += ((n[0] + 2) & 4) << 1;
    for (unsigned int i = 32; i >= 8; i /= 2) {
        x *= (2u - (n[0] * x));
    }
    return ~x + 1;
}

static size_t mpi_msb(const mbedtls_mpi *X) {
    if (X != NULL && X->MBEDTLS_PRIVATE(n) != 0) {
        for (int i = (int)X->MBEDTLS_PRIVATE(n) - 1; i >= 0; i--) {
            uint32_t limb = X->MBEDTLS_PRIVATE(p)[i];
            if (limb != 0) {
                for (int j = 31; j >= 0; j--) {
                    if (limb & (1u << j)) {
                        return (size_t)(i * 32 + j);
                    }
                }
            }
        }
    }
    return 0;
}

bool rsa_mpi_set_words(mbedtls_mpi *X, const uint32_t *words, size_t n_words) {
    if (mbedtls_mpi_grow(X, n_words) != 0) {
        return false;
    }
    memcpy(X->MBEDTLS_PRIVATE(p), words, n_words * sizeof(uint32_t));
    X->MBEDTLS_PRIVATE(s) = 1;
    return true;
}

void rsa_mpi_get_words(const mbedtls_mpi *X, uint32_t *words, size_t n_words) {
    size_t copy_words = X->MBEDTLS_PRIVATE(n);
    if (copy_words > n_words) {
        copy_words = n_words;
    }
    memset(words, 0, n_words * sizeof(uint32_t));
    memcpy(words, X->MBEDTLS_PRIVATE(p), copy_words * sizeof(uint32_t));
}

bool rsa_mont_ctx_init(rsa_mont_ctx_t *ctx, const uint32_t *M_words, size_t words) {
    if (!ctx || !M_words || words == 0) {
        return false;
    }
    if ((M_words[0] & 1u) == 0) {
        return false;
    }

    ctx->words = words;
    ctx->hw_words = esp_mpi_hardware_words(words);
    mbedtls_mpi_init(&ctx->M);
    mbedtls_mpi_init(&ctx->Rinv);

    if (!rsa_mpi_set_words(&ctx->M, M_words, words)) {
        rsa_mont_ctx_free(ctx);
        return false;
    }

    if (mbedtls_mpi_lset(&ctx->Rinv, 1) != 0) {
        rsa_mont_ctx_free(ctx);
        return false;
    }
    if (mbedtls_mpi_shift_l(&ctx->Rinv, ctx->hw_words * 2 * 32) != 0) {
        rsa_mont_ctx_free(ctx);
        return false;
    }
    if (mbedtls_mpi_mod_mpi(&ctx->Rinv, &ctx->Rinv, &ctx->M) != 0) {
        rsa_mont_ctx_free(ctx);
        return false;
    }

    ctx->mprime = montmul_init_u32(ctx->M.MBEDTLS_PRIVATE(p));
    return true;
}

void rsa_mont_ctx_free(rsa_mont_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    mbedtls_mpi_free(&ctx->M);
    mbedtls_mpi_free(&ctx->Rinv);
    ctx->words = 0;
    ctx->hw_words = 0;
    ctx->mprime = 0;
}

bool rsa_mod_mult_hw_ctx(const rsa_mont_ctx_t *ctx,
                         const mbedtls_mpi *X, const mbedtls_mpi *Y,
                         mbedtls_mpi *Z) {
    if (!ctx || !X || !Y || !Z) {
        return false;
    }

    esp_mpi_enable_hardware_hw_op();
    esp_mpi_mul_mpi_mod_hw_op(X, Y, &ctx->M, &ctx->Rinv, ctx->mprime, ctx->hw_words);
    if (mbedtls_mpi_grow(Z, ctx->hw_words) != 0) {
        esp_mpi_disable_hardware_hw_op();
        return false;
    }
    mpi_hal_read_result_hw_op(Z->MBEDTLS_PRIVATE(p), Z->MBEDTLS_PRIVATE(n), ctx->hw_words);
    esp_mpi_disable_hardware_hw_op();
    return true;
}

bool rsa_mod_exp_hw_ctx(const rsa_mont_ctx_t *ctx,
                        const mbedtls_mpi *X, const mbedtls_mpi *E,
                        mbedtls_mpi *Z, bool feed_wdt) {
    if (!ctx || !X || !E || !Z) {
        return false;
    }
    (void)feed_wdt;
    if (mbedtls_mpi_cmp_int(E, 0) == 0) {
        return mbedtls_mpi_lset(Z, 1) == 0;
    }

    mbedtls_mpi X_mont;
    mbedtls_mpi one;
    mbedtls_mpi_init(&X_mont);
    mbedtls_mpi_init(&one);

    if (mbedtls_mpi_grow(&X_mont, ctx->hw_words) != 0 ||
        mbedtls_mpi_grow(Z, ctx->hw_words) != 0 ||
        mbedtls_mpi_grow(&one, ctx->hw_words) != 0 ||
        mbedtls_mpi_set_bit(&one, 0, 1) != 0) {
        mbedtls_mpi_free(&X_mont);
        mbedtls_mpi_free(&one);
        return false;
    }

    int t = (int)mpi_msb(E);
    esp_mpi_enable_hardware_hw_op();

    // X_mont = mont(X, R^2 mod M) = X * R mod M
    if (esp_mont_hw_op(&X_mont, X, &ctx->Rinv, &ctx->M, ctx->mprime, ctx->hw_words, false) != 0) {
        esp_mpi_disable_hardware_hw_op();
        mbedtls_mpi_free(&X_mont);
        mbedtls_mpi_free(&one);
        return false;
    }

    // Z = R mod M
    if (esp_mont_hw_op(Z, &ctx->Rinv, &one, &ctx->M, ctx->mprime, ctx->hw_words, true) != 0) {
        esp_mpi_disable_hardware_hw_op();
        mbedtls_mpi_free(&X_mont);
        mbedtls_mpi_free(&one);
        return false;
    }

    for (int i = t; i >= 0; i--) {
        if (i != t) {
            if (esp_mont_hw_op(Z, Z, Z, &ctx->M, ctx->mprime, ctx->hw_words, true) != 0) {
                esp_mpi_disable_hardware_hw_op();
                mbedtls_mpi_free(&X_mont);
                mbedtls_mpi_free(&one);
                return false;
            }
        }

        if (mbedtls_mpi_get_bit(E, i)) {
            if (esp_mont_hw_op(Z, Z, &X_mont, &ctx->M, ctx->mprime, ctx->hw_words, true) != 0) {
                esp_mpi_disable_hardware_hw_op();
                mbedtls_mpi_free(&X_mont);
                mbedtls_mpi_free(&one);
                return false;
            }
        }
    }

    // Convert back from Montgomery domain
    if (esp_mont_hw_op(Z, Z, &one, &ctx->M, ctx->mprime, ctx->hw_words, true) != 0) {
        esp_mpi_disable_hardware_hw_op();
        mbedtls_mpi_free(&X_mont);
        mbedtls_mpi_free(&one);
        return false;
    }

    esp_mpi_disable_hardware_hw_op();
    mbedtls_mpi_free(&X_mont);
    mbedtls_mpi_free(&one);
    return true;
}

void generate_random_4096_odd(uint32_t *num) {
    uint8_t *bytes = (uint8_t *)num;
    
    for (int i = 0; i < RSA_4096_BYTES; i++) {
        bytes[i] = esp_random() & 0xFF;
    }
    
    // Ensure positive
    num[RSA_4096_WORDS - 1] &= 0x7FFFFFFF;
    
    // Ensure not zero
    if (num[RSA_4096_WORDS - 1] == 0) {
        num[RSA_4096_WORDS - 1] = 0x00000001;
    }
    
    // Ensure odd
    num[0] |= 0x01;
}

void print_4096_sample(const char* label, const uint32_t *num) {
    printf("%s: [0x%08" PRIX32 " ... 0x%08" PRIX32 "]\n",
           label, num[RSA_4096_WORDS - 1], num[0]);
}

bool is_zero_4096(const uint32_t *num) {
    for (int i = 0; i < RSA_4096_WORDS; i++) {
        if (num[i] != 0) return false;
    }
    return true;
}

void rsa_periph_enable(bool enable) {
    if (enable) {
        esp_mpi_enable_hardware_hw_op();
    } else {
        esp_mpi_disable_hardware_hw_op();
    }
}

bool rsa_write_block(uint32_t block_addr, const uint32_t *data) {
    volatile uint32_t *block = (volatile uint32_t *)block_addr;
    for (int i = 0; i < RSA_4096_WORDS; i++) {
        block[i] = data[i];
    }
    return true;
}

bool rsa_read_block(uint32_t block_addr, uint32_t *data) {
    volatile uint32_t *block = (volatile uint32_t *)block_addr;
    for (int i = 0; i < RSA_4096_WORDS; i++) {
        data[i] = block[i];
    }
    return true;
}

bool test_memory_access(void) {
    printf("\n[TEST] Memory Access Test:\n");
    
    rsa_periph_enable(true);
    
    volatile uint32_t *x_mem = (volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;
    uint32_t test_value = 0xDEADBEEF;
    bool success = true;
    
    // Test write/read
    x_mem[0] = test_value;
    uint32_t read_value = x_mem[0];
    
    printf("  Write: 0x%08" PRIX32 "\n", test_value);
    printf("  Read:  0x%08" PRIX32 "\n", read_value);
    
    if (read_value != test_value) {
        printf("  ✗ Memory access FAILED\n");
        success = false;
    } else {
        printf("  ✓ Memory access PASSED\n");
    }
    
    rsa_periph_enable(false);
    return success;
}
