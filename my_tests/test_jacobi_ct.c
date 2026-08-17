#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

/* Declare your Jacobi implementation */
extern int ossl_bn_jacobi_by(const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

/* Test parameter configurations */
#define BIT_LENGTH 1024         /* Number of bits for testing */
#define POOL_SIZE 1000          /* Size of the pool */
#define TEST_ITERATIONS 60000  /* Number of measurements per round */

BN_CTX *bn_ctx;
BIGNUM *fixed_prime;               /* Added: Fixed prime used for Mode 0 */
BIGNUM *prime_pool[POOL_SIZE];     /* Prime pool (denominator n) */
BIGNUM *composite_pool[POOL_SIZE]; /* Composite pool (denominator n) */
BIGNUM **input_x_array;

BIGNUM *fixed_base_a;              /* Fixed numerator a */

/* Global variable: Controls the evaluation mode */
int eval_mode = 2; /* 0: fixed, 1: pool, 2: composite (default) */

/*
 * Sampling preparation function supporting three modes
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
    }
}

uint8_t do_one_computation(uint8_t *data) {
    size_t index = *(size_t *)data;
    
    /* Call Jacobi implementation: (fixed_base_a / input_x_array[index]) */
    ossl_bn_jacobi_by(fixed_base_a, input_x_array[index], bn_ctx);
    
    return 0;
}

int main(int argc, char *argv[]) {
    /* Parse command-line arguments */
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

    /* 1. Initialize data */
    printf("--- Fair Test Preparation (Jacobi: %s) ---\n", mode_str);
    
    /* Generate fixed numerator a (slightly shorter to ensure a < n) */
    printf("Generating Fixed Base 'a'...\n");
    BN_rand(fixed_base_a, BIT_LENGTH - 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);

    printf("Generating Fixed Prime (Class 0 for fixed mode)...\n");
    BN_generate_prime_ex(fixed_prime, BIT_LENGTH, 0, NULL, NULL, NULL);

    printf("Generating Prime Pool & Composite Pool (%d each, STRICT %d-bit)...\n", POOL_SIZE, BIT_LENGTH);
    for (int i = 0; i < POOL_SIZE; i++) {
        /* Generate exact BIT_LENGTH prime */
        prime_pool[i] = BN_new();
        BN_generate_prime_ex(prime_pool[i], BIT_LENGTH, 0, NULL, NULL, NULL);

        /* Generate exact BIT_LENGTH odd composite */
        composite_pool[i] = BN_new();
        do {
            /* BN_RAND_TOP_ONE ensures the highest bit is 1 (exact bit length)
             * BN_RAND_BOTTOM_ODD ensures the lowest bit is 1 (must be odd) */
            BN_rand(composite_pool[i], BIT_LENGTH, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        } while (BN_check_prime(composite_pool[i], bn_ctx, NULL) == 1); /* Ensure it is truly composite */

        if (i > 0 && i % (POOL_SIZE / 5) == 0) {
            printf("Progress: %d%%\n", (i * 100) / POOL_SIZE);
        }
    }

    /* 2. Dudect configuration */
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

    printf("\nStarting FAIR dudect analysis for Jacobi Symbol...\n");
    printf("Mode: %s\n", mode_str);

    /* Execute enough loops to ensure dudect collects sufficient samples to output data */
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (int i = 0; i < 50; i++) {
        dudect_main(&ctx);
    }

    /* 3. Cleanup */
    dudect_free(&ctx);
    for (size_t i = 0; i < conf.number_measurements; i++) BN_free(input_x_array[i]);
    for (int i = 0; i < POOL_SIZE; i++) {
        BN_free(prime_pool[i]);
        BN_free(composite_pool[i]);
    }
    free(input_x_array);
    free(fixed_base_a);
    free(fixed_prime);
    BN_CTX_free(bn_ctx);

    return 0;
}