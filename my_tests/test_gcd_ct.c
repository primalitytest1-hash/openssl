#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

/* 🔥 宣告你的 GCD/Inversion 實作與記憶體擴展工具 */
extern void ct_by_gcd_inv(BIGNUM *out_inv, BIGNUM *out_gcd, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx);
extern BIGNUM *bn_wexpand(BIGNUM *a, int words);

/* 測試參數設定 */
#define BIT_LENGTH 1024         /* 測試位元數 */
#define POOL_SIZE 1000          /* 池子大小 */
#define TEST_ITERATIONS 60000  /* 單輪測量次數 */

BN_CTX *bn_ctx;
BIGNUM *fixed_prime;               /* 用於 Mode 0 的固定質數 */
BIGNUM *prime_pool[POOL_SIZE];     /* 質數池 (分母 m) */
BIGNUM *composite_pool[POOL_SIZE]; /* 合數池 (分母 m) */
BIGNUM **input_x_array;

BIGNUM *fixed_base_a;              /* 固定的分子 x */
BIGNUM *out_inv;                   /* 預先分配：接反元素的容器 */
BIGNUM *out_gcd;                   /* 預先分配：接 GCD 的容器 */
int top_w;                         /* 全域記憶體長度 */

/* 全域變數：控制測試模式 */
int eval_mode = 2; /* 0: fixed, 1: pool, 2: composite (預設) */

/*
 * 🛠️ 支援三種模式的抽樣準備函數 (準備階段不計入執行時間)
 */
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(classes, c->number_measurements);

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] &= 1;
        size_t *idx_ptr = (size_t *)(input_data + i * c->chunk_size);
        *idx_ptr = i;

        if (classes[i] == 0) {
            /* Class 0 */
            if (eval_mode == 0) {
                BN_copy(input_x_array[i], fixed_prime);
            } else if (eval_mode == 1) {
                BN_copy(input_x_array[i], prime_pool[rand() % (POOL_SIZE / 2)]);
            } else {
                BN_copy(input_x_array[i], prime_pool[rand() % POOL_SIZE]);
            }
        } else {
            /* Class 1 */
            if (eval_mode == 0) {
                BN_copy(input_x_array[i], prime_pool[rand() % POOL_SIZE]);
            } else if (eval_mode == 1) {
                BN_copy(input_x_array[i], prime_pool[(POOL_SIZE / 2) + (rand() % (POOL_SIZE / 2))]);
            } else {
                BN_copy(input_x_array[i], composite_pool[rand() % POOL_SIZE]);
            }
        }
        
        /* 🚨 極度重要：在進入計時區前，確保剛拷貝好的數字內部記憶體已撐開到 top_w */
        bn_wexpand(input_x_array[i], top_w);
    }
}

/*
 * ⏱️ 實際計時區塊：越乾淨越好，只能有演算法本身
 */
uint8_t do_one_computation(uint8_t *data) {
    size_t index = *(size_t *)data;
    
    /* 🚨 呼叫最新的 Binary GCD/Inversion 實作 */
    ct_by_gcd_inv(out_inv, out_gcd, fixed_base_a, input_x_array[index], top_w, bn_ctx);
    
    return 0;
}

int main(int argc, char *argv[]) {
    /* 解析命令列參數 */
    if (argc == 2) {
        if (strcmp(argv[1], "fixed") == 0) eval_mode = 0;
        else if (strcmp(argv[1], "pool") == 0) eval_mode = 1;
        else if (strcmp(argv[1], "composite") == 0) eval_mode = 2;
        else {
            printf("Usage: %s [fixed | pool | composite]\n", argv[0]);
            return 1;
        }
    } else {
        printf("Usage: %s [fixed | pool | composite]\n", argv[0]);
        printf("Defaulting to 'composite' mode.\n\n");
    }

    const char *mode_str = (eval_mode == 0) ? "Fixed Prime vs Prime Pool" :
                           (eval_mode == 1) ? "Prime Pool vs Prime Pool" :
                                              "Prime Pool vs Composite Pool";

    bn_ctx = BN_CTX_new();
    fixed_base_a = BN_new();
    fixed_prime = BN_new();
    out_inv = BN_new();
    out_gcd = BN_new();

    /* 計算我們目標位元數對應的 Limb 數量 (top_w) */
    top_w = (BIT_LENGTH + BN_BITS2 - 1) / BN_BITS2;
    
    /* 預先撐開輸出容器，避免在計時區內觸發 malloc */
    bn_wexpand(out_inv, top_w);
    bn_wexpand(out_gcd, top_w);

    /* 1. 初始化資料 */
    printf("--- Fair Test Preparation (GCD/Inversion: %s) ---\n", mode_str);
    
    printf("Generating Fixed Base 'x'...\n");
    BN_rand(fixed_base_a, BIT_LENGTH - 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    bn_wexpand(fixed_base_a, top_w);

    printf("Generating Fixed Prime (Class 0 for fixed mode)...\n");
    BN_generate_prime_ex(fixed_prime, BIT_LENGTH, 0, NULL, NULL, NULL);

    printf("Generating Prime Pool & Composite Pool (%d each, STRICT %d-bit)...\n", POOL_SIZE, BIT_LENGTH);
    for (int i = 0; i < POOL_SIZE; i++) {
        prime_pool[i] = BN_new();
        BN_generate_prime_ex(prime_pool[i], BIT_LENGTH, 0, NULL, NULL, NULL);

        composite_pool[i] = BN_new();
        do {
            BN_rand(composite_pool[i], BIT_LENGTH, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        } while (BN_check_prime(composite_pool[i], bn_ctx, NULL) == 1); 

        if (i > 0 && i % (POOL_SIZE / 5) == 0) {
            printf("Progress: %d%%\n", (i * 100) / POOL_SIZE);
        }
    }

    /* 2. Dudect 設定 */
    dudect_config_t conf = {
        .chunk_size = sizeof(size_t),
        .number_measurements = TEST_ITERATIONS
    };

    input_x_array = malloc(conf.number_measurements * sizeof(BIGNUM *));
    for (size_t i = 0; i < conf.number_measurements; i++) {
        input_x_array[i] = BN_new();
    }

    dudect_ctx_t ctx;
    dudect_init(&ctx, &conf);

    printf("\nStarting FAIR dudect analysis for Constant-Time GCD/Inversion...\n");
    printf("Mode: %s\n", mode_str);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (int i = 0; i < 3; i++) {
        dudect_main(&ctx);
    }

    /* 3. 清理 */
    dudect_free(&ctx);
    for (size_t i = 0; i < conf.number_measurements; i++) BN_free(input_x_array[i]);
    for (int i = 0; i < POOL_SIZE; i++) {
        BN_free(prime_pool[i]);
        BN_free(composite_pool[i]);
    }
    free(input_x_array);
    free(fixed_base_a);
    free(fixed_prime);
    free(out_inv);
    free(out_gcd);
    BN_CTX_free(bn_ctx);

    return 0;
}