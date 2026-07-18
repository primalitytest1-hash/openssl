#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <sys/time.h>

/* --- Supplement OpenSSL Internal Constants --- */
#define BN_PRIMETEST_COMPOSITE                    0
#define BN_PRIMETEST_COMPOSITE_WITH_FACTOR        1
#define BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME 2
#define BN_PRIMETEST_PROBABLY_PRIME               3
/* --------------------------------------------- */

/* Declare OpenSSL Internal Primality Testing Functions */
extern int ossl_bn_CHVL_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);
extern int ossl_bn_miller_rabin_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int enhanced, int *status);
extern int ossl_bn_solovay_strassen_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 🔥 Declare the newly written Fully-Padded Constant-Time Miller-Rabin */
extern int ossl_bn_miller_rabin_is_prime_unified(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 🔥🔥 Declare the latest CCS 2026 Hybrid Version (Amortized SS + Vset) */
extern int ossl_bn_CHVSS_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 🔥🔥🔥 Declare OpenSSL built-in and the newly written Constant-Time Jacobi */
extern int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
extern int ossl_bn_jacobi_by(const BIGNUM *x_in, const BIGNUM *y_in, BN_CTX *ctx);

/* 🔥🔥🔥 Declare the Constant-Time Binary GCD (Extracted from Lucas Test) */
extern void ct_by_invert(BIGNUM *out, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx);
extern void ct_by_gcd_inv(BIGNUM *out_inv, BIGNUM *out_gcd, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx);


/* 🛠️ Supplement missing OpenSSL internal function declarations (for BIGNUM memory manipulation) */
extern BIGNUM *bn_wexpand(BIGNUM *a, int words);
extern void bn_correct_top(BIGNUM *a);


/* Time Calculation Auxiliary Function */
long long timeval_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000000LL + (end->tv_usec - start->tv_usec);
}

/* Test 1: Functional Equivalence Test (MR vs MR-FP vs Lucas vs SS vs Hybrid) */
void run_correctness_test(int num_tests, int bits) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *w = BN_new();
    int status_mr, status_mr_fp, status_lucas, status_ss, status_hybrid;
    int match_count = 0, prime_count = 0;

    printf("==================================================\n");
    printf("1. Starting functional equivalence test (%d rounds, %d-bit)...\n", num_tests, bits);

    for (int i = 0; i < num_tests; i++) {
        /* Generate a random odd number */
        BN_rand(w, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);

        /* Call original Miller-Rabin (64 iterations) */
        ossl_bn_miller_rabin_is_prime(w, 64, ctx, NULL, 0, &status_mr);
        
        /* Call Fully-Padded CT Miller-Rabin (64 iterations) */
        ossl_bn_miller_rabin_is_prime_unified(w, 64, ctx, NULL, &status_mr_fp);

        /* Call the CHVL Lucas test (66 iterations) */
        ossl_bn_CHVL_is_prime(w, 66, ctx, NULL, &status_lucas);

        /* Call Solovay-Strassen test (128 iterations) */
        ossl_bn_solovay_strassen_is_prime(w, 128, ctx, NULL, &status_ss);

        /* Call the latest Hybrid SS+Vset test (68 iterations: 7 SS + 61 Vset) */
        ossl_bn_CHVSS_is_prime(w, 68, ctx, NULL, &status_hybrid);

        /* Verify if all five results match perfectly */
        int is_prime_mr      = (status_mr == BN_PRIMETEST_PROBABLY_PRIME);
        int is_prime_mr_fp   = (status_mr_fp == BN_PRIMETEST_PROBABLY_PRIME);
        int is_prime_lucas   = (status_lucas == BN_PRIMETEST_PROBABLY_PRIME);
        int is_prime_ss      = (status_ss == BN_PRIMETEST_PROBABLY_PRIME);
        int is_prime_hybrid  = (status_hybrid == BN_PRIMETEST_PROBABLY_PRIME);

        if ((is_prime_mr != is_prime_lucas) || 
            (is_prime_mr != is_prime_ss) || 
            (is_prime_mr != is_prime_mr_fp) || 
            (is_prime_mr != is_prime_hybrid)) {
            
            printf("[FAILED] Mismatch found!\n");
            printf("MR says: %d, MR-FP says: %d, Lucas says: %d, SS says: %d, Hybrid says: %d\n", 
                   is_prime_mr, is_prime_mr_fp, is_prime_lucas, is_prime_ss, is_prime_hybrid);
            char *w_str = BN_bn2hex(w);
            printf("Failed Number: %s\n", w_str);
            OPENSSL_free(w_str);
            exit(1);
        }

        if (is_prime_mr) prime_count++;
        match_count++;
    }

    printf("[SUCCESS] All %d tests matched perfectly. Found %d primes.\n", match_count, prime_count);
    
    BN_free(w);
    BN_CTX_free(ctx);
}

/* Test 2: Performance Benchmark Test */
void run_performance_benchmark(int num_tests, int bits) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *w = BN_new();
    int status;
    struct timeval start, end;
    long long time_mr = 0, time_mr_fp = 0, time_lucas = 0, time_ss = 0, time_hybrid = 0;

    printf("\n==================================================\n");
    printf("2. Starting performance benchmark (%d inputs, %d-bit)...\n", num_tests, bits);
    printf("   (Aligned to 2^-128 security level)\n");
    printf("   - MR (Baseline)    : 64 iters\n");
    printf("   - SS (Pure)        : 128 iters\n");
    printf("   - CHVL   : 66 iters\n");
    printf("   - CHVSS : 68 iters (7 SS + 61 Vset)\n");
    printf("--------------------------------------------------\n");

    BN_generate_prime_ex(w, bits, 0, NULL, NULL, NULL);

    gettimeofday(&start, NULL);
    for (int i = 0; i < num_tests; i++) {
        ossl_bn_miller_rabin_is_prime(w, 64, ctx, NULL, 0, &status);
    }
    gettimeofday(&end, NULL);
    time_mr = timeval_diff(&start, &end);

    gettimeofday(&start, NULL);
    for (int i = 0; i < num_tests; i++) {
        ossl_bn_miller_rabin_is_prime_unified(w, 64, ctx, NULL, &status);
    }
    gettimeofday(&end, NULL);
    time_mr_fp = timeval_diff(&start, &end);

    gettimeofday(&start, NULL);
    for (int i = 0; i < num_tests; i++) {
        ossl_bn_CHVL_is_prime(w, 66, ctx, NULL, &status);
    }
    gettimeofday(&end, NULL);
    time_lucas = timeval_diff(&start, &end);

    gettimeofday(&start, NULL);
    for (int i = 0; i < num_tests; i++) {
        ossl_bn_solovay_strassen_is_prime(w, 128, ctx, NULL, &status);
    }
    gettimeofday(&end, NULL);
    time_ss = timeval_diff(&start, &end);

    gettimeofday(&start, NULL);
    for (int i = 0; i < num_tests; i++) {
        ossl_bn_CHVSS_is_prime(w, 68, ctx, NULL, &status);
    }
    gettimeofday(&end, NULL);
    time_hybrid = timeval_diff(&start, &end);

    printf("--- Benchmark Results (Total Microseconds) ---\n");
    printf("Miller-Rabin (Raw): %lld us\n", time_mr);
    printf("Miller-Rabin (FP) : %lld us\n", time_mr_fp);
    printf("Solovay-Strass.   : %lld us\n", time_ss);
    printf("CHVL Time : %lld us\n", time_lucas);
    printf("CHVSS Time  : %lld us\n", time_hybrid);
    
    printf("\n--- Performance Overheads (Normalized to Raw MR) ---\n");
    printf("MR (Baseline)     : 1.00x\n");
    printf("MR (Unified FP)   : %.2fx\n", (double)time_mr_fp / time_mr);
    printf("Solovay-Strassen  : %.2fx\n", (double)time_ss / time_mr);
    printf("CHVL    : %.2fx\n", (double)time_lucas / time_mr);
    printf("CHVSS  : %.2fx\n", (double)time_hybrid / time_mr);
    printf("==================================================\n");

    BN_free(w);
    BN_CTX_free(ctx);
}

/* Test 3: Jacobi Correctness Comparison (OpenSSL vs CT BY) */
void run_correctness_jacobi_test(int num_tests, int bits) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    int status_ref, status_ct;
    int match_count = 0;

    printf("\n==================================================\n");
    printf("3. Starting Jacobi functional equivalence test (%d rounds, %d-bit)...\n", num_tests, bits);

    for (int i = 0; i < num_tests; i++) {
        BN_rand(x, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_rand(y, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);

        if (i % 4 == 0) BN_set_negative(x, 1);
        if (i % 4 == 1) BN_set_negative(y, 1);
        if (i % 4 == 2) { BN_set_negative(x, 1); BN_set_negative(y, 1); }

        status_ref = BN_kronecker(x, y, ctx);
        status_ct = ossl_bn_jacobi_by(x, y, ctx);

        if (status_ref != status_ct) {
            printf("[FAILED] Jacobi Mismatch found!\n");
            printf("OpenSSL says: %d, CT BY says: %d\n", status_ref, status_ct);
            char *x_str = BN_bn2hex(x);
            char *y_str = BN_bn2hex(y);
            printf("Failed X: %s\n", x_str);
            printf("Failed Y: %s\n", y_str);
            OPENSSL_free(x_str);
            OPENSSL_free(y_str);
            exit(1);
        }
        match_count++;
    }

    printf("[SUCCESS] All %d Jacobi tests matched perfectly.\n", match_count);
    
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
}

/* Test 4: GCD/Inversion Correctness Comparison (OpenSSL vs CT Binary GCD) */
void run_correctness_gcd_test(int num_tests, int bits) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *gcd_ref = BN_new();
    BIGNUM *gcd_ct = BN_new();
    BIGNUM *inv_ref = BN_new();
    BIGNUM *inv_ct = BN_new();
    int match_count = 0;

    printf("\n==================================================\n");
    printf("4. Starting GCD/Inversion equivalence test (%d rounds, %d-bit)...\n", num_tests, bits);

    for (int i = 0; i < num_tests; i++) {
        /* Generate two random numbers of the same bit length (b is guaranteed odd) */
        BN_rand(a, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BN_rand(b, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);

        /* 1. Calculate GCD using OpenSSL built-in function */
        BN_gcd(gcd_ref, a, b, ctx);

        /* 2. Use the Constant-Time Binary GCD algorithm.
         * Note: We need to expand a and b to the same top_w before feeding to ct_by_invert */
        int top_w = (bits + BN_BITS2 - 1) / BN_BITS2;
        
        /* 🚀 Fix Segfault: Pre-allocate all internal arrays to the required length! */
        bn_wexpand(a, top_w);
        bn_wexpand(b, top_w);
        bn_wexpand(gcd_ct, top_w); 
        bn_wexpand(inv_ct, top_w);
        
        /* ct_by_invert will write the result into the pre-allocated gcd_ct array */
        ct_by_gcd_inv(inv_ct, gcd_ct, a, b, top_w, ctx);

        /* For comparison, we need to remove leading zeros from the returned gcd_ct (normalize) */
        bn_correct_top(gcd_ct);
        bn_correct_top(inv_ct);

        /* 3. Compare results */
        if (BN_cmp(gcd_ref, gcd_ct) != 0) {
            printf("[FAILED] GCD Mismatch found!\n");
            char *a_str = BN_bn2hex(a);
            char *b_str = BN_bn2hex(b);
            char *ref_str = BN_bn2hex(gcd_ref);
            char *ct_str = BN_bn2hex(gcd_ct);
            printf("Input A: %s\n", a_str);
            printf("Input B: %s\n", b_str);
            printf("OpenSSL GCD: %s\n", ref_str);
            printf("CT BY GCD  : %s\n", ct_str);
            OPENSSL_free(a_str); OPENSSL_free(b_str);
            OPENSSL_free(ref_str); OPENSSL_free(ct_str);
            exit(1);
        }

        /* 4. Additionally compare if the modular inverse is correct */
        if (BN_is_one(gcd_ref)) {
            BN_mod_inverse(inv_ref, a, b, ctx); 
            if (BN_cmp(inv_ref, inv_ct) != 0) {
                printf("[FAILED] Modular Inverse Mismatch found!\n");
                exit(1);
            }
        }

        match_count++;
    }

    printf("[SUCCESS] All %d GCD & Inversion tests matched perfectly.\n", match_count);
    
    BN_free(a);
    BN_free(b);
    BN_free(gcd_ref);
    BN_free(gcd_ct);
    BN_free(inv_ref);
    BN_free(inv_ct);
    BN_CTX_free(ctx);
}

/* Main Program: Triggers all tests */
int main(int argc, char **argv) {
    
    /* Execute correctness comparison: 500 iterations of 512-bit random numbers */
    run_correctness_test(500, 512);

    /* 🔥 Added: Execute Jacobi correctness comparison test */
    run_correctness_jacobi_test(5000, 2048);
    
    /* 🔥 Added: Execute GCD/Inversion correctness comparison test */
    //run_correctness_gcd_test(10000, 512);

    /* Execute performance benchmark test */
    /* Note: For the paper, it is recommended to test 2048-bit 100 times to demonstrate the true power of large number multiplication */
    run_performance_benchmark(6000, 2048);

    run_performance_benchmark(6000, 1536);

    run_performance_benchmark(6000, 1024);
    
    return 0;
}