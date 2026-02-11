idf_component_register(SRCS "main.c" "rsa_hw.c" "rsa_debug.c" "rsa_benchmark.c" "sha_benchmark.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_timer esp_system
                    PRIV_REQUIRES mbedtls)
