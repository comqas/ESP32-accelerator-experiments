# ESP32 Accelerator Experiments

Benchmarks for 2048- and 4096-bit modular multiplication and modular exponentiation using the ESP32 RSA hardware accelerator, plus SHA hashing benchmarks using the hardware SHA engine. This project was built to support the ARUP protocol experiments and emphasizes fixed-modulus measurements with precomputed Montgomery constants.

**What it measures**
- Modular multiplication with a fixed modulus (random multiplicands only)
- Modular exponentiation with a small exponent near 20000 (product of up to 5 primes > 2)
- Modular exponentiation with a full-domain exponent (random full-length exponent)
- SHA256 timing for message lengths 32..16384 bytes
- Full-domain hash timing using SHA512 x4 (2048-bit output) and SHA512 x8 (4096-bit output)

**Key methodology**
- The modulus is fixed per bit-size during each benchmark suite run.
- Montgomery constants (`Rinv`, `Mprime`) are precomputed once per modulus.
- Output includes per-iteration CSV rows and summary CSV lines.
- Hash benchmarks measure end-to-end API timing (setup + hashing + output read-back).
- Full-domain hash appends a 1-byte counter per hash and concatenates outputs.

**Build and run**
```sh
cd ~/esp/modular_benchmark
. ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/cu.usbserial-01ED9F2A flash monitor
```

**Output format**
- Per-iteration rows: `CSV,op,bits,exp,iter,us`
- Summary rows: `CSV_SUMMARY,op,bits,exp,iter,success,avg_us,min_us,max_us,stddev_us`
- SHA256 rows: `CSV_SHA256,len,total_us,setup_us,per_byte_us`
- Full-domain hash rows: `CSV_FDH,output_bits,len,total_us,setup_us,per_byte_us,bytes_processed`

**Configuration**
- Iteration counts and enabled benchmarks are configured in `~/esp/modular_benchmark/main/main.c`.
- The small exponent is computed as the product of up to 5 of the first 9 primes > 2, chosen closest to 20000.
- Full-domain exponent is a random full-length exponent for the selected bit-size.
- Task Watchdog is disabled during benchmarking to avoid long-run interruptions.
- Hash benchmark lengths are configured in `~/esp/modular_benchmark/main/sha_benchmark.c`.

**License**
GPL-3.0-or-later (see `LICENSE`).
