# ESP32 Accelerator Experiments

Benchmarks for 2048- and 4096-bit modular multiplication and modular exponentiation using the ESP32 RSA hardware accelerator. This project was built to support the ARUP protocol experiments and emphasizes fixed-modulus measurements with precomputed Montgomery constants.

**What it measures**
- Modular multiplication with a fixed modulus (random multiplicands only)
- Modular exponentiation with a small exponent near 20000 (product of up to 5 primes > 2)
- Modular exponentiation with a full-domain exponent (random full-length exponent)

**Key methodology**
- The modulus is fixed per bit-size during each benchmark suite run.
- Montgomery constants (`Rinv`, `Mprime`) are precomputed once per modulus.
- Output includes per-iteration CSV rows and summary CSV lines.

**Build and run**
```sh
cd /Users/comqas/esp/modular_benchmark
. /Users/comqas/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/cu.usbserial-01ED9F2A flash monitor
```

**Output format**
- Per-iteration rows: `CSV,op,bits,exp,iter,us`
- Summary rows: `CSV_SUMMARY,op,bits,exp,iter,success,avg_us,min_us,max_us,stddev_us`

**Configuration**
- Iteration counts and enabled benchmarks are configured in `/Users/comqas/esp/modular_benchmark/main/main.c`.
- The small exponent is computed as the product of up to 5 of the first 9 primes > 2, chosen closest to 20000.
- Full-domain exponent is a random full-length exponent for the selected bit-size.
- Task Watchdog is disabled during benchmarking to avoid long-run interruptions.

**License**
GPL-3.0-or-later (see `LICENSE`).
