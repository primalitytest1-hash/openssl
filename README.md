# Aligning the Trace: Structurally Constant-Time Primality Testing against Misalignment Attacks

This repository contains the source code, custom implementations, and benchmarking suites required to reproduce the experimental results presented in **Section 6** our paper. It provides the tools to evaluate the correctness, performance, and side-channel resilience of our proposed primality tests: **HVL** and **HVSS**.

## 1. Overview of the Experiments

As detailed in the paper, our experimental evaluation is divided into two primary domains to prove both the efficiency and the structural security of our architectures:

1. **Performance and Correctness Verification (Section 6.1 & 6.2):** Evaluates the functional equivalence and execution latencies of our  implementations (HVL and HVSS) against the native OpenSSL Miller-Rabin (MR), a constant-time Miller-Rabin, and a constant-time Solovay-Strassen baseline. 

2. **Constant-Time Leakage Assessment (Section 6.2):** Utilizes the `dudect` framework to rigorously verify the constant-time execution of our algorithms over 600,000 timing measurements. The tests assess three distinct leakage vectors (Fixed vs. Pool, Pool vs. Pool, Prime vs. Composite) to ensure the maximum Welch's t-statistic remains strictly within the +/- 4.5 safety threshold.

> **Prerequisite:** Before running any of the tests below, please ensure that you have successfully configured and compiled the modified OpenSSL library (`libcrypto.a`) in the root directory.

---

## 2. Correctness and Performance Benchmark (Section 6.1 & 6.2)

This suite executes the functional equivalence verifications across all five algorithms and measures their execution times across different prime bit-lengths (1024, 1536, and 2048-bit). 

### Compilation
Navigate to the root directory of the repository and compile the benchmark harness:
```bash
gcc -O2 test_prime_tests.c -I./include ./libcrypto.a -lpthread -ldl -o test_prime_tests
```

### Execution
Run the compiled benchmark:
```bash
./test_prime_tests
```
*The terminal output will display the absolute execution times  and the normalized performance overheads relative to the vulnerable baseline, directly reproducing the data for Table 5 and Figure 2.*

---

## 3. Constant-Time Leakage Assessment (dudect)

We integrate the `dudect` framework to perform rigorous side-channel leakage assessments. 

### Compilation
Navigate to the `my_tests` directory and compile the leakage assessment tool:
```bash
cd my_tests/
gcc -O2 test_all_ct.c -o test_all_ct -I../include -I./dudect/src ../libcrypto.a -lm
```

### Execution
Execute the side-channel test:
```bash
./test_all_ct
```
*The tool will compute Welch's t-test statistic. A maximum t-statistic value of `< 4.5` indicates no statistically significant timing leakage.*

---

## 4. Cross-Platform Configuration (ARM64 vs. x86_64)

To demonstrate that our design's side-channel resilience is independent of specific microarchitectures, we evaluated it on both ARM64 and x86_64 platforms. 

By default, the `dudect` environment in this repository is configured to read cycle counts for **ARM64** (e.g., Apple M-series processors). 

### Switching to x86_64
1. Open the file `dudect/src/cpucycles.h`.
2. Locate the `cpucycles()` function definition.
3. Replace the ARM64 inline assembly with the x86_64 `rdtsc` instruction implementation.

**For ARM64 (Default):**
```c
static inline int64_t cpucycles(void) {
    int64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}
```

**For x86_64:**
```c
static inline int64_t cpucycles(void) {
    unsigned int hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
}
```

*After updating the cycle counter, recompile the `test_all_ct.c` binary on your x86_64 machine and execute it to reproduce the results in Figure 1.*