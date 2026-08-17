# Fixed-Depth Lucas Primality Testing with Near-MR Soundness

This repository contains the source code, custom implementations, and benchmarking suites required to reproduce the experimental results presented in **Section 6** our paper. It provides the tools to evaluate the correctness, performance, and side-channel resilience of our proposed primality tests: **HFDL** and **HFDSS**.

## 1. Overview of the Experiments

As detailed in the paper, our experimental evaluation is divided into two primary domains to prove both the efficiency and the structural security of our architectures:

1. **Performance and Correctness Verification (Section 6.1 & 6.2):** Evaluates the functional equivalence and execution latencies of our  implementations (HFDL and HFDSS) against the native OpenSSL Miller-Rabin (MR), a constant-time Miller-Rabin, and a constant-time Solovay-Strassen baseline. 

2. **Constant-Time Leakage Assessment (Section 6.2):** Utilizes the `dudect` framework to rigorously verify the constant-time execution of our algorithms over 600,000 timing measurements. The tests assess three distinct leakage vectors (Fixed vs. Pool, Pool vs. Pool, Prime vs. Composite) to ensure the maximum Welch's t-statistic remains strictly within the +/- 4.5 safety threshold.

> **Prerequisite:** Before running any of the tests below, please ensure that you have successfully configured and compiled the modified OpenSSL library (`libcrypto.a`) in the root directory.

---

## 2. Correctness and Performance Benchmark (Section 6.1 & 6.2)

This suite executes the functional equivalence verifications across all five algorithms and measures their execution times across different prime bit-lengths (1024, 1536, and 2048-bit). 

### Compilation
Navigate to the root directory of the repository and compile the benchmark harness:
```bash
gcc -O2 test_prime_tests.c -I./include ./libcrypto.a -lpthread -ldl -o test_prime_tests