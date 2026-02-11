#include "rsa_hw.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/dport_reg.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/bignum.h"
#include "bignum_impl.h"
#include "hal/mpi_hal.h"

static const char* TAG = "RSA_DEBUG";

// ==================== DEBUGGING FUNCTIONS ====================

void print_rsa_registers(const char* label) {
    printf("\n%s:\n", label);
    uint32_t clean_reg = DPORT_REG_READ(RSA_QUERY_CLEAN_REG);
    printf("  QUERY_CLEAN_REG:      0x%08" PRIX32, clean_reg);
    printf(" (bit0=%d, bit1=%d)\n", (clean_reg & 0x1) ? 1 : 0, (clean_reg & 0x2) ? 1 : 0);
    printf("  QUERY_INTERRUPT_REG:  0x%08" PRIX32 "\n", DPORT_REG_READ(RSA_QUERY_INTERRUPT_REG));
    printf("  MULT_MODE_REG:        0x%08" PRIX32 "\n", DPORT_REG_READ(RSA_MULT_MODE_REG));
    printf("  MULT_START_REG:       0x%08" PRIX32 "\n", DPORT_REG_READ(RSA_MULT_START_REG));
}

static uint32_t montmul_init_u32(const uint32_t *n) {
    uint32_t x = n[0];
    x += ((n[0] + 2) & 4) << 1;
    for (unsigned int i = 32; i >= 8; i /= 2) {
        x *= (2u - (n[0] * x));
    }
    return ~x + 1;
}

static bool mpi_from_words(mbedtls_mpi *X, const uint32_t *words, size_t n_words) {
    int ret = mbedtls_mpi_grow(X, n_words);
    if (ret != 0) {
        return false;
    }
    memcpy(X->MBEDTLS_PRIVATE(p), words, n_words * sizeof(uint32_t));
    X->MBEDTLS_PRIVATE(s) = 1;
    return true;
}

static uint64_t modmul_u64(uint64_t a, uint64_t b, uint64_t mod) {
    if (mod == 0) {
        return 0;
    }
    uint64_t res = 0;
    uint64_t x = a % mod;
    uint64_t y = b;
    while (y > 0) {
        if (y & 1u) {
            res = (res + x) % mod;
        }
        x = (x << 1) % mod;
        y >>= 1;
    }
    return res;
}

static uint64_t modexp_u64(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 0) {
        return 0;
    }
    uint64_t result = 1 % mod;
    uint64_t b = base % mod;
    uint64_t e = exp;
    while (e > 0) {
        if (e & 1u) {
            result = modmul_u64(result, b, mod);
        }
        b = modmul_u64(b, b, mod);
        e >>= 1;
    }
    return result;
}

// DEBUGGING NEEDED: This is the core function that doesn't work correctly
bool rsa_mod_mult_hw(const uint32_t *X, const uint32_t *Y, 
                     const uint32_t *M, uint32_t *Z) {
    if ((M[0] & 1u) == 0) {
        ESP_LOGE(TAG, "Modulus must be odd");
        return false;
    }

    bool ok = false;
    int ret;
    size_t hw_words = esp_mpi_hardware_words(RSA_4096_WORDS);

    mbedtls_mpi X_mpi, Y_mpi, M_mpi, Rinv_mpi, Z_mpi;
    mbedtls_mpi_init(&X_mpi);
    mbedtls_mpi_init(&Y_mpi);
    mbedtls_mpi_init(&M_mpi);
    mbedtls_mpi_init(&Rinv_mpi);
    mbedtls_mpi_init(&Z_mpi);

    if (!mpi_from_words(&X_mpi, X, RSA_4096_WORDS) ||
        !mpi_from_words(&Y_mpi, Y, RSA_4096_WORDS) ||
        !mpi_from_words(&M_mpi, M, RSA_4096_WORDS)) {
        goto cleanup;
    }

    ret = mbedtls_mpi_lset(&Rinv_mpi, 1);
    if (ret != 0) {
        goto cleanup;
    }
    ret = mbedtls_mpi_shift_l(&Rinv_mpi, hw_words * 2 * 32);
    if (ret != 0) {
        goto cleanup;
    }
    ret = mbedtls_mpi_mod_mpi(&Rinv_mpi, &Rinv_mpi, &M_mpi);
    if (ret != 0) {
        goto cleanup;
    }

    uint32_t mprime = montmul_init_u32((const uint32_t *)M_mpi.MBEDTLS_PRIVATE(p));

    esp_mpi_enable_hardware_hw_op();
    esp_mpi_mul_mpi_mod_hw_op(&X_mpi, &Y_mpi, &M_mpi, &Rinv_mpi, mprime, hw_words);
    ret = mbedtls_mpi_grow(&Z_mpi, hw_words);
    if (ret == 0) {
        mpi_hal_read_result_hw_op(Z_mpi.MBEDTLS_PRIVATE(p), Z_mpi.MBEDTLS_PRIVATE(n), hw_words);
        memset(Z, 0, RSA_4096_WORDS * sizeof(uint32_t));
        memcpy(Z, Z_mpi.MBEDTLS_PRIVATE(p), hw_words * sizeof(uint32_t));
        ok = true;
    }
    esp_mpi_disable_hardware_hw_op();

cleanup:
    mbedtls_mpi_free(&X_mpi);
    mbedtls_mpi_free(&Y_mpi);
    mbedtls_mpi_free(&M_mpi);
    mbedtls_mpi_free(&Rinv_mpi);
    mbedtls_mpi_free(&Z_mpi);
    return ok;
}

bool rsa_mod_exp_hw(const uint32_t *X, const uint32_t *E,
                    const uint32_t *M, uint32_t *Z) {
    if ((M[0] & 1u) == 0) {
        ESP_LOGE(TAG, "Modulus must be odd");
        return false;
    }

    bool ok = false;
    int ret;
    mbedtls_mpi X_mpi, E_mpi, M_mpi, Z_mpi;
    mbedtls_mpi_init(&X_mpi);
    mbedtls_mpi_init(&E_mpi);
    mbedtls_mpi_init(&M_mpi);
    mbedtls_mpi_init(&Z_mpi);

    if (!mpi_from_words(&X_mpi, X, RSA_4096_WORDS) ||
        !mpi_from_words(&E_mpi, E, RSA_4096_WORDS) ||
        !mpi_from_words(&M_mpi, M, RSA_4096_WORDS)) {
        goto cleanup;
    }

    ret = mbedtls_mpi_exp_mod(&Z_mpi, &X_mpi, &E_mpi, &M_mpi, NULL);
    if (ret == 0) {
        memset(Z, 0, RSA_4096_WORDS * sizeof(uint32_t));
        size_t copy_words = Z_mpi.MBEDTLS_PRIVATE(n);
        if (copy_words > RSA_4096_WORDS) {
            copy_words = RSA_4096_WORDS;
        }
        memcpy(Z, Z_mpi.MBEDTLS_PRIVATE(p), copy_words * sizeof(uint32_t));
        ok = true;
    } else {
        ESP_LOGE(TAG, "mbedtls_mpi_exp_mod failed: -0x%04X", (unsigned)(-ret));
    }

cleanup:
    mbedtls_mpi_free(&X_mpi);
    mbedtls_mpi_free(&E_mpi);
    mbedtls_mpi_free(&M_mpi);
    mbedtls_mpi_free(&Z_mpi);
    return ok;
}

bool verify_hw_sw_small_mult(size_t iterations) {
    printf("\n[CHECK] Small-value mod-mult vs software reference:\n");

    uint32_t X[RSA_4096_WORDS] = {0};
    uint32_t Y[RSA_4096_WORDS] = {0};
    uint32_t M[RSA_4096_WORDS] = {0};
    uint32_t Z[RSA_4096_WORDS] = {0};

    for (size_t i = 0; i < iterations; i++) {
        uint64_t x = (uint64_t)esp_random();
        uint64_t y = (uint64_t)esp_random();
        uint64_t m = ((uint64_t)esp_random()) | 1u;
        if (m < 3) {
            m |= 3u;
        }

        memset(X, 0, sizeof(X));
        memset(Y, 0, sizeof(Y));
        memset(M, 0, sizeof(M));
        X[0] = (uint32_t)x;
        Y[0] = (uint32_t)y;
        M[0] = (uint32_t)m;

        uint64_t ref = modmul_u64(x, y, m);

        if (!rsa_mod_mult_hw(X, Y, M, Z)) {
            printf("  ✗ HW mod-mult failed at iter %zu\n", i);
            return false;
        }

        bool rest_zero = true;
        for (int w = 1; w < RSA_4096_WORDS; w++) {
            if (Z[w] != 0) {
                rest_zero = false;
                break;
            }
        }

        if (Z[0] != (uint32_t)ref || !rest_zero) {
            printf("  ✗ Mismatch at iter %zu (ref=%" PRIu32 ", got=%" PRIu32 ")\n",
                   i, (uint32_t)ref, Z[0]);
            return false;
        }
    }

    printf("  ✓ %zu/%zu passed\n", iterations, iterations);
    return true;
}

bool verify_hw_sw_small_exp(size_t iterations) {
    printf("\n[CHECK] Small-value mod-exp vs software reference:\n");

    uint32_t X[RSA_4096_WORDS] = {0};
    uint32_t E[RSA_4096_WORDS] = {0};
    uint32_t M[RSA_4096_WORDS] = {0};
    uint32_t Z[RSA_4096_WORDS] = {0};

    for (size_t i = 0; i < iterations; i++) {
        uint64_t x = (uint64_t)esp_random();
        uint64_t e = (uint64_t)esp_random();
        if (e == 0) {
            e = 3;
        }
        uint64_t m = ((uint64_t)esp_random()) | 1u;
        if (m < 3) {
            m |= 3u;
        }

        memset(X, 0, sizeof(X));
        memset(E, 0, sizeof(E));
        memset(M, 0, sizeof(M));
        X[0] = (uint32_t)x;
        E[0] = (uint32_t)e;
        M[0] = (uint32_t)m;

        uint64_t ref = modexp_u64(x, e, m);

        if (!rsa_mod_exp_hw(X, E, M, Z)) {
            printf("  ✗ HW mod-exp failed at iter %zu\n", i);
            return false;
        }

        bool rest_zero = true;
        for (int w = 1; w < RSA_4096_WORDS; w++) {
            if (Z[w] != 0) {
                rest_zero = false;
                break;
            }
        }

        if (Z[0] != (uint32_t)ref || !rest_zero) {
            printf("  ✗ Mismatch at iter %zu (ref=%" PRIu32 ", got=%" PRIu32 ")\n",
                   i, (uint32_t)ref, Z[0]);
            return false;
        }
    }

    printf("  ✓ %zu/%zu passed\n", iterations, iterations);
    return true;
}

// Simple test to debug hardware issues
void debug_simple_hardware_test(void) {
    printf("\n[DEBUG] Simple Hardware Test:\n");
    
    // Use small numbers in 4096-bit buffers
    uint32_t X[RSA_4096_WORDS] = {0};
    uint32_t Y[RSA_4096_WORDS] = {0};
    uint32_t M[RSA_4096_WORDS] = {0};
    uint32_t Z[RSA_4096_WORDS] = {0};
    
    X[0] = 0x00000002;  // 2
    Y[0] = 0x00000003;  // 3
    M[0] = 0x00000005;  // 5 (odd)
    M[0] |= 1;
    
    printf("Testing: (2 * 3) mod 5 = 1\n");
    print_4096_sample("X", X);
    print_4096_sample("Y", Y);
    print_4096_sample("M", M);
    
    rsa_periph_enable(true);
    print_rsa_registers("Before operation");
    rsa_periph_enable(false);

    bool success = rsa_mod_mult_hw(X, Y, M, Z);

    rsa_periph_enable(true);
    print_rsa_registers("After operation");
    rsa_periph_enable(false);
    
    if (success) {
        print_4096_sample("Result Z", Z);
        printf("Expected: [0x00000000 ... 0x00000001]\n");
        
        bool rest_zero = true;
        for (int i = 1; i < RSA_4096_WORDS; i++) {
            if (Z[i] != 0) {
                rest_zero = false;
                break;
            }
        }

        if (Z[0] == 0x00000001 && rest_zero) {
            printf("✓ Hardware test PASSED\n");
        } else {
            printf("✗ Hardware test FAILED (wrong result)\n");
        }
    } else {
        printf("✗ Hardware operation failed\n");
    }
}
