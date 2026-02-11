#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "rsa_hw.h"

void app_main(void) {
    printf("\n\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║    ESP32 RSA Hardware Benchmark    ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    
    vTaskDelay(pdMS_TO_TICKS(3000));
    
    printf("System Information:\n");
    printf("  Free Heap: %" PRIu32 " bytes\n", esp_get_free_heap_size());
    printf("  RSA 4096-bit: %d words, %d bytes\n", RSA_4096_WORDS, RSA_4096_BYTES);
    
    // Step 1: Test basic memory access (WORKING)
    printf("\n══════════════════════════════════════════\n");
    printf("Step 1: Basic Memory Access Test\n");
    printf("══════════════════════════════════════════\n");
    
    // Use the return value to avoid unused variable warning
    if (!test_memory_access()) {
        printf("Memory test failed! Stopping.\n");
        return;
    }
    
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    
    // Step 2: Correctness checks vs software reference (small values)
    printf("\n══════════════════════════════════════════\n");
    printf("Step 2: Correctness Checks\n");
    printf("══════════════════════════════════════════\n");

    if (!verify_hw_sw_small_mult(5) || !verify_hw_sw_small_exp(5)) {
        printf("Correctness checks failed! Stopping.\n");
        return;
    }

    vTaskDelay(1000 / portTICK_PERIOD_MS);

    // Step 3: Debug simple hardware test
    printf("\n══════════════════════════════════════════\n");
    printf("Step 3: Debug Hardware Operation\n");
    printf("══════════════════════════════════════════\n");
    
    debug_simple_hardware_test();
    
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    
    // Step 4: Run benchmarks (fixed modulus, precomputed Montgomery constants)
    printf("\n══════════════════════════════════════════\n");
    printf("Step 4: Performance Benchmarks\n");
    printf("══════════════════════════════════════════\n");

    if (esp_task_wdt_deinit() == ESP_OK) {
        printf("Task WDT disabled for benchmarking\n");
    }

    printf("CSV_HEADER,op,bits,exp,iter,us\n");
    printf("CSV_SUMMARY_HEADER,op,bits,exp,iter,success,avg_us,min_us,max_us,stddev_us\n");

    const size_t iter_mult_2048 = 20;
    const size_t iter_mult_4096 = 50;
    const size_t iter_exp_small_2048 = 10;
    const size_t iter_exp_small_4096 = 20;
    const size_t iter_exp_full_2048 = 10;
    const size_t iter_exp_full_4096 = 50;

    benchmark_suite_fixed_mod(2048, iter_mult_2048, iter_exp_small_2048, iter_exp_full_2048);
    benchmark_suite_fixed_mod(4096, iter_mult_4096, iter_exp_small_4096, iter_exp_full_4096);
    
    printf("\n══════════════════════════════════════════\n");
    printf("Benchmark Complete!\n");
    printf("══════════════════════════════════════════\n\n");
    
    while (1) {
        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}
