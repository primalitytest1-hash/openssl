#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

/* 🔥 新增：宣告 Unified Single-Loop MR 函式 */
extern int ossl_bn_miller_rabin_is_prime_unified(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

/* 測試參數設定 */
#define BIT_LENGTH 256         /* 降到 512-bit 提高測試速度 */
#define PRIME_POOL_SIZE 100    /* 質數池大小，確保 Class 1 數值有多樣性 */
#define TEST_ITERATIONS 20000  /* 總測量次數 */

BN_CTX *bn_ctx;
BIGNUM *fixed_prime;           /* Class 0 用的固定質數 */
BIGNUM *prime_pool[PRIME_POOL_SIZE]; /* Class 1 用的質數池 */
BIGNUM **input_x_array;

/* 🔥 新增：用來控制要跑哪一個實作的全域變數 */
int run_unified = 0;

/*
 * 🛠️ 修改後的準備函數：現在 Class 1 是從質數池中隨機抽取的
 */
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(classes, c->number_measurements);

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] &= 1;
        size_t *idx_ptr = (size_t *)(input_data + i * c->chunk_size);
        *idx_ptr = i;

        if (classes[i] == 0) {
            /* Class 0: 永遠使用同一個質數 A */
            BN_copy(input_x_array[i], fixed_prime);
        } else {
            /* Class 1: 從預先生成的池中隨機抽一個質數 B */
            /* 這樣兩邊都保證會跑完 64 輪 Miller-Rabin */
            int pool_idx = rand() % PRIME_POOL_SIZE;
            BN_copy(input_x_array[i], prime_pool[pool_idx]);
        }
    }
}

// /*
//  * 🛠️ 修正後的隔離測試：固定模數 N，驗證內部 Ladder 的恆定性
//  */
// void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
//     randombytes(classes, c->number_measurements);
//
//     for (size_t i = 0; i < c->number_measurements; i++) {
//         classes[i] &= 1;
//         size_t *idx_ptr = (size_t *)(input_data + i * c->chunk_size);
//         *idx_ptr = i;
//
//         /* 🔥 控制變因：Class 0 與 Class 1 都餵同一個固定質數 🔥 */
//         /* 因為你的 Lucas 函式內部會自動生成隨機底數 P 
//          * 這樣就能精確證明：無論內部隨機底數 P 是多少，你的程式碼執行時間都是恆定的！ */
//         BN_copy(input_x_array[i], fixed_prime);
//     }
// }

uint8_t do_one_computation(uint8_t *data) {
    size_t index = *(size_t *)data;
    int status = 0;
    
    /* 🔥 新增：根據全域變數決定呼叫哪一個實作 */
    if (run_unified) {
        ossl_bn_miller_rabin_is_prime_unified(input_x_array[index], 64, bn_ctx, NULL, &status);
    } else {
        /* 呼叫原生 Miller-Rabin */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        BN_is_prime_ex(input_x_array[index], 64, bn_ctx, NULL);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    /* 🔥 新增：極簡的參數判斷，不破壞你原本的流程 */
    if (argc == 2 && strcmp(argv[1], "unified") == 0) {
        run_unified = 1;
        printf(">>> Target: Unified Single-Loop Miller-Rabin <<<\n");
    } else {
        printf(">>> Target: Native OpenSSL Miller-Rabin <<<\n");
        printf("(Hint: Run '%s unified' to test the Unified MR)\n\n", argv[0]);
    }

    bn_ctx = BN_CTX_new();
    fixed_prime = BN_new();

    /* 1. 初始化質數池 */
    printf("--- Fair Test Preparation ---\n");
    printf("Generating Fixed Prime for Class 0...\n");
    BN_generate_prime_ex(fixed_prime, BIT_LENGTH, 0, NULL, NULL, NULL);

    printf("Generating Prime Pool (%d primes) for Class 1...\n", PRIME_POOL_SIZE);
    for (int i = 0; i < PRIME_POOL_SIZE; i++) {
        prime_pool[i] = BN_new();
        BN_generate_prime_ex(prime_pool[i], BIT_LENGTH, 0, NULL, NULL, NULL);
        if (i % 20 == 0) printf("Progress: %d%%\n", (i * 100) / PRIME_POOL_SIZE);
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

    printf("\nStarting FAIR dudect analysis (Prime vs. Prime Pool)...\n");

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (int i = 0; i < 5; i++) {
        state = dudect_main(&ctx);
        if (state == DUDECT_LEAKAGE_FOUND) {
            printf("\nLeakage detected! Aborting.\n");
            break;
        }
    }

    /* 3. 清理 */
    dudect_free(&ctx);
    for (size_t i = 0; i < conf.number_measurements; i++) BN_free(input_x_array[i]);
    for (int i = 0; i < PRIME_POOL_SIZE; i++) BN_free(prime_pool[i]);
    free(input_x_array);
    BN_free(fixed_prime);
    BN_CTX_free(bn_ctx);

    return 0;
}