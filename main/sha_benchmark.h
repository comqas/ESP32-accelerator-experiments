#pragma once

#include <stddef.h>

void benchmark_sha256_lengths(size_t iterations);
void benchmark_full_domain_hash(size_t output_bits, size_t iterations);
