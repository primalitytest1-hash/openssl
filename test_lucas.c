#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <sys/time.h>

/* --- 補齊 OpenSSL 內部常數 --- */
#define BN_PRIMETEST_COMPOSITE                    0
#define BN_PRIMETEST_COMPOSITE_WITH_FACTOR        1
#define BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME 2
#define BN_PRIMETEST_PROBABLY_PRIME               3
/* --------------------------------------------- */

/* * 宣告 OpenSSL 內部的質數測試函數 */
extern int ossl_bn_lucas_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);
extern int ossl_bn_miller_rabin_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int enhanced, int *status);
extern int ossl_bn_solovay_strassen_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 🔥 宣告您新寫的 Fully-Padded Constant-Time Miller-Rabin */
extern int ossl_bn_miller_rabin_is_prime_unified(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 🔥🔥 宣告您最新的 CCS 2026 混合動力版 (Amortized SS + Vset) */
extern int ossl_bn_ss_vset_hybrid_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 🔥🔥🔥 宣告 OpenSSL 內建的與您新寫的 Constant-Time Jacobi */
extern int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
extern int ossl_bn_jacobi_by(const BIGNUM *x_in, const BIGNUM *y_in, BN_CTX *ctx);

/* 🔥🔥🔥 宣告您的 Constant-Time Binary GCD (提取自 Lucas Test) */
extern void ct_by_invert(BIGNUM *out, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx);
extern void ct_by_gcd_inv(BIGNUM *out_inv, BIGNUM *out_gcd, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx);


/* 🛠️ 補齊缺失的 OpenSSL 內部函數宣告 (用來操作 BIGNUM 記憶體) */
extern BIGNUM *bn_wexpand(BIGNUM *a, int words);
extern void bn_correct_top(BIGNUM *a);


/* 時間計算輔助函數 */
long long timeval_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000000LL + (end->tv_usec - start->tv_usec);
}

/* 測試一：正確性比對 (MR vs MR-FP vs Lucas vs SS vs Hybrid) */
void run_correctness_test(int num_tests, int bits) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *w = BN_new();
    int status_mr, status_mr_fp, status_lucas, status_ss, status_hybrid;
    int match_count = 0, prime_count = 0;

    printf("==================================================\n");
    printf("1. Starting functional equivalence test (%d rounds, %d-bit)...\n", num_tests, bits);

    for (int i = 0; i < num_tests; i++) {
        /* 隨機生成一個奇數 */
        BN_rand(w, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);

        /* 呼叫原本的 Miller-Rabin (跑 64 圈) */
        ossl_bn_miller_rabin_is_prime(w, 64, ctx, NULL, 0, &status_mr);
        
        /* 呼叫 Fully-Padded CT Miller-Rabin (跑 64 圈) */
        ossl_bn_miller_rabin_is_prime_unified(w, 64, ctx, NULL, &status_mr_fp);

        /* 呼叫你的原始 Lucas 測試 (跑 64 圈) */
        ossl_bn_lucas_is_prime(w, 64, ctx, NULL, &status_lucas);

        /* 呼叫 Solovay-Strassen 測試 (跑 64 圈) */
        ossl_bn_solovay_strassen_is_prime(w, 64, ctx, NULL, &status_ss);

        /* 呼叫最新的 Hybrid SS+Vset 測試 (跑 68 圈: 8 SS + 60 Vset) */
        ossl_bn_ss_vset_hybrid_is_prime(w, 68, ctx, NULL, &status_hybrid);

        /* 驗證五者結果是否一致 */
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

/* 測試二：效能基準測試 */
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
    printf("   - Proposed Lucas   : 66 iters\n");
    printf("   - Amortized Hybrid : 69 iters (8 SS + 61 Vset)\n");
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
        ossl_bn_lucas_is_prime(w, 66, ctx, NULL, &status);
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
        ossl_bn_ss_vset_hybrid_is_prime(w, 69, ctx, NULL, &status);
    }
    gettimeofday(&end, NULL);
    time_hybrid = timeval_diff(&start, &end);

    printf("--- Benchmark Results (Total Microseconds) ---\n");
    printf("Miller-Rabin (Raw): %lld us\n", time_mr);
    printf("Miller-Rabin (FP) : %lld us\n", time_mr_fp);
    printf("Solovay-Strass.   : %lld us\n", time_ss);
    printf("Lucas Ladder Time : %lld us\n", time_lucas);
    printf("Hybrid SS+Vset    : %lld us  <-- YOUR PAPER'S HERO\n", time_hybrid);
    
    printf("\n--- Performance Overheads (Normalized to Raw MR) ---\n");
    printf("MR (Baseline)     : 1.00x\n");
    printf("MR (Unified FP)   : %.2fx\n", (double)time_mr_fp / time_mr);
    printf("Solovay-Strassen  : %.2fx\n", (double)time_ss / time_mr);
    printf("Proposed Lucas    : %.2fx\n", (double)time_lucas / time_mr);
    printf("Amortized Hybrid  : %.2fx\n", (double)time_hybrid / time_mr);
    printf("==================================================\n");

    BN_free(w);
    BN_CTX_free(ctx);
}

/* 測試三：Jacobi 正確性比對 (OpenSSL vs CT BY) */
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

/* 測試四：GCD/Inversion 正確性比對 (OpenSSL vs CT Binary GCD) */
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
        /* 生成兩個位元數相同的隨機數 (b 保證為奇數) */
        BN_rand(a, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BN_rand(b, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);

        /* 1. 使用 OpenSSL 內建函式求 GCD */
        BN_gcd(gcd_ref, a, b, ctx);

        /* 2. 使用你的常數時間 Binary GCD 演算法
         * 注意：我們需要把 a 和 b 撐到相同的 top_w，才能餵給 ct_by_invert */
        int top_w = (bits + BN_BITS2 - 1) / BN_BITS2;
        
        /* 🚀 修正 Segfault：預先分配所有的內部陣列到需要的長度！ */
        bn_wexpand(a, top_w);
        bn_wexpand(b, top_w);
        bn_wexpand(gcd_ct, top_w); 
        bn_wexpand(inv_ct, top_w);
        
        /* ct_by_invert 執行完會把結果蓋進 gcd_ct 預留好的陣列中 */
        ct_by_gcd_inv(inv_ct, gcd_ct, a, b, top_w, ctx);

        /* 為了比較，我們需要將回傳的 gcd_ct 去除前導零 (normalize) */
        bn_correct_top(gcd_ct);
        bn_correct_top(inv_ct);

        /* 3. 比較結果 */
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

        /* 4. 加碼比對反元素是否正確 */
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

/* 主程式：負責啟動所有測試 */
int main(int argc, char **argv) {
    
    /* 執行正確性對比：測 500 次 512-bit 隨機數字 */
    run_correctness_test(500, 512);

    /* 🔥 新增：執行 Jacobi 正確性對比測試 */
    run_correctness_jacobi_test(5000, 2048);
    
    /* 🔥 新增：執行 GCD/Inversion 正確性對比測試 */
    run_correctness_gcd_test(10000, 512);

    /* 執行效能測試：測 600 次 512-bit 質數 */
    /* 備註：在論文中建議改為 2048-bit 測 100 次，以展現大數乘法的真實威力 */
    run_performance_benchmark(5000, 2048);

    run_performance_benchmark(5000, 1536);

    run_performance_benchmark(5000, 1024);
    
    return 0;
}