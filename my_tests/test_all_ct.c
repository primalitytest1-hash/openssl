#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

/* --- 1. 完全對齊你提供的 OpenSSL 原始宣告 --- */
extern int ossl_bn_miller_rabin_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
                                          BN_GENCB *cb, int enhanced, int *status);

/* 其他演算法宣告 */
extern int ossl_bn_lucas_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);
extern int ossl_bn_solovay_strassen_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);
extern int ossl_bn_miller_rabin_is_prime_unified(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);
extern int ossl_bn_ss_vset_hybrid_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx, BN_GENCB *cb, int *status);

#define BIT_LENGTH 1024         
#define PRIME_POOL_SIZE 1000   
#define TEST_ITERATIONS 20000  

/* --- 檔案名稱定義 --- */
#define FILE_FIXED  "dataset_fixed_prime.hex"
#define FILE_PRIMES "dataset_prime_pool.hex"
#define FILE_COMPS  "dataset_composite_pool.hex"

BN_CTX *bn_ctx;
BIGNUM *fixed_prime;           
BIGNUM *prime_pool[PRIME_POOL_SIZE]; 
BIGNUM *composite_pool[PRIME_POOL_SIZE]; 
BIGNUM **input_x_array;

int test_mode = 0; // 0: lucas, 1: mrunified, 2: hybrid, 3: ss, 4: mr (native)
int eval_type = 0; // 0: fixed, 1: pool, 2: composite

/* --- 資料集存取函數 --- */
int load_datasets() {
    FILE *f_fixed = fopen(FILE_FIXED, "r");
    FILE *f_primes = fopen(FILE_PRIMES, "r");
    FILE *f_comps = fopen(FILE_COMPS, "r");
    
    if (!f_fixed || !f_primes || !f_comps) {
        if (f_fixed) fclose(f_fixed);
        if (f_primes) fclose(f_primes);
        if (f_comps) fclose(f_comps);
        return 0; // 檔案不齊全，需要重新生成
    }
    
    char buffer[2048]; // 足以容納 1024-bit 的 hex 字串與換行符
    
    if (fgets(buffer, sizeof(buffer), f_fixed)) {
        BN_hex2bn(&fixed_prime, buffer);
    }
    fclose(f_fixed);
    
    for (int i = 0; i < PRIME_POOL_SIZE; i++) {
        if (fgets(buffer, sizeof(buffer), f_primes)) {
            prime_pool[i] = BN_new();
            BN_hex2bn(&prime_pool[i], buffer);
        }
        if (fgets(buffer, sizeof(buffer), f_comps)) {
            composite_pool[i] = BN_new();
            BN_hex2bn(&composite_pool[i], buffer);
        }
    }
    fclose(f_primes);
    fclose(f_comps);
    return 1;
}

void save_datasets() {
    FILE *f_fixed = fopen(FILE_FIXED, "w");
    FILE *f_primes = fopen(FILE_PRIMES, "w");
    FILE *f_comps = fopen(FILE_COMPS, "w");
    
    char *hex = BN_bn2hex(fixed_prime);
    fprintf(f_fixed, "%s\n", hex);
    OPENSSL_free(hex);
    fclose(f_fixed);
    
    for (int i = 0; i < PRIME_POOL_SIZE; i++) {
        hex = BN_bn2hex(prime_pool[i]);
        fprintf(f_primes, "%s\n", hex);
        OPENSSL_free(hex);
        
        hex = BN_bn2hex(composite_pool[i]);
        fprintf(f_comps, "%s\n", hex);
        OPENSSL_free(hex);
    }
    fclose(f_primes);
    fclose(f_comps);
}

/* --- Dudect 函數 --- */
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(classes, c->number_measurements);
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] &= 1;
        size_t *idx_ptr = (size_t *)(input_data + i * c->chunk_size);
        *idx_ptr = i;
        if (classes[i] == 0) {
            if (eval_type == 0) BN_copy(input_x_array[i], fixed_prime);
            else if (eval_type == 1) BN_copy(input_x_array[i], prime_pool[rand() % (PRIME_POOL_SIZE / 2)]);
            else BN_copy(input_x_array[i], prime_pool[rand() % PRIME_POOL_SIZE]);
        } else {
            if (eval_type == 0) BN_copy(input_x_array[i], prime_pool[rand() % PRIME_POOL_SIZE]);
            else if (eval_type == 1) BN_copy(input_x_array[i], prime_pool[(PRIME_POOL_SIZE / 2) + (rand() % (PRIME_POOL_SIZE / 2))]);
            else BN_copy(input_x_array[i], composite_pool[rand() % PRIME_POOL_SIZE]);
        }
    }
}

uint8_t do_one_computation(uint8_t *data) {
    size_t index = *(size_t *)data;
    int status = 0;
    
    if (test_mode == 0) ossl_bn_lucas_is_prime(input_x_array[index], 66, bn_ctx, NULL, &status);
    else if (test_mode == 1) ossl_bn_miller_rabin_is_prime_unified(input_x_array[index], 64, bn_ctx, NULL, &status);
    else if (test_mode == 2) ossl_bn_ss_vset_hybrid_is_prime(input_x_array[index], 69, bn_ctx, NULL, &status);
    else if (test_mode == 3) ossl_bn_solovay_strassen_is_prime(input_x_array[index], 128, bn_ctx, NULL, &status);
    else if (test_mode == 4) ossl_bn_miller_rabin_is_prime(input_x_array[index], 64, bn_ctx, NULL, 0, &status);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s [lucas|mrunified|hybrid|ss|mr] [fixed|pool|composite]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "lucas") == 0) test_mode = 0;
    else if (strcmp(argv[1], "mrunified") == 0) test_mode = 1;
    else if (strcmp(argv[1], "hybrid") == 0) test_mode = 2;
    else if (strcmp(argv[1], "ss") == 0) test_mode = 3;
    else if (strcmp(argv[1], "mr") == 0) test_mode = 4;

    if (strcmp(argv[2], "fixed") == 0) eval_type = 0;
    else if (strcmp(argv[2], "pool") == 0) eval_type = 1;
    else if (strcmp(argv[2], "composite") == 0) eval_type = 2;

    bn_ctx = BN_CTX_new();
    fixed_prime = BN_new();

    printf("--- YOUR Test Preparation (%d-bit) ---\n", BIT_LENGTH);
    
    /* 核心修改：如果檔案存在就讀取，不存在就生成並存檔 */
    if (!load_datasets()) {
        printf("Datasets not found. Generating new pools and saving to files...\n");
        BN_generate_prime_ex(fixed_prime, BIT_LENGTH, 0, NULL, NULL, NULL);
        for (int i = 0; i < PRIME_POOL_SIZE; i++) {
            prime_pool[i] = BN_new();
            BN_generate_prime_ex(prime_pool[i], BIT_LENGTH, 0, NULL, NULL, NULL);
            composite_pool[i] = BN_new();
            do { BN_rand(composite_pool[i], BIT_LENGTH, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
            } while (BN_check_prime(composite_pool[i], bn_ctx, NULL) == 1);
        }
        save_datasets();
        printf("Successfully generated and saved datasets!\n");
    } else {
        printf("Successfully loaded identical datasets from hex files!\n");
    }

    dudect_config_t conf = { .chunk_size = sizeof(size_t), .number_measurements = TEST_ITERATIONS };
    input_x_array = malloc(conf.number_measurements * sizeof(BIGNUM *));
    for (size_t i = 0; i < conf.number_measurements; i++) input_x_array[i] = BN_new();

    dudect_ctx_t ctx; dudect_init(&ctx, &conf);
    printf("\nStarting FAIR dudect analysis: %s vs %s...\n", argv[1], argv[2]);

    for (int i = 0; i < 30; i++) {
        dudect_main(&ctx);
    }

    /* 記憶體釋放 */
    dudect_free(&ctx);
    for (size_t i = 0; i < conf.number_measurements; i++) BN_free(input_x_array[i]);
    free(input_x_array);
    for (int i = 0; i < PRIME_POOL_SIZE; i++) {
        BN_free(prime_pool[i]);
        BN_free(composite_pool[i]);
    }
    BN_free(fixed_prime);
    BN_CTX_free(bn_ctx);

    return 0;
}