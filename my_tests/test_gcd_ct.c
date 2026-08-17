#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

/* Declare your GCD/Inversion implementation and memory expansion tool */
extern void ct_by_gcd_inv(BIGNUM *out_inv, BIGNUM *out_gcd, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx);
extern BIGNUM *bn_wexpand(BIGNUM *a, int words);

/* Test parameter configurations */
#define BIT_LENGTH 1024         /* Number of bits for testing */
#define POOL_SIZE 1000          /* Size of the pool */
#define TEST_ITERATIONS 60000  /* Number of measurements per round */

BN_CTX *bn_ctx;
BIGNUM *fixed_prime;               /* Fixed prime used for Mode 0 */
BIGNUM *prime_pool[POOL_SIZE];     /* Prime pool (denominator m) */
BIGNUM *composite_pool[POOL_SIZE]; /* Composite pool (denominator m) */
BIGNUM **input_x_array;

BIGNUM *fixed_base_a;              /* Fixed numerator x */
BIGNUM *out_inv;                   /* Pre-allocated: container for the modular inverse */
BIGNUM *out_gcd;                   /* Pre-allocated: container for the GCD */
int top_w;                         /* Global memory length (number of limbs) */

/* Global variable: Controls the evaluation mode */
int eval_mode = 2; /* 0: fixed, 1: pool, 2: composite (default) */

/*
 * Sampling preparation function supporting three modes (Preparation phase is excluded from timing)
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
        
        /* 🚨 Extremely Important: Before entering the timed section, ensure the internal memory of the newly copied number is expanded to top_w */
        bn_wexpand(input_x_array[i], top_w);
    }
}

/*
 * Actual timed section: Keep it as clean as possible, only the algorithm itself should be present
 */
uint8_t do_one_computation(uint8_t *data) {
    size_t index = *(size_t *)data;
    
    /* Call the latest Constant-Time Binary GCD/Inversion implementation */
    ct_by_gcd_inv(out_inv, out_gcd, fixed_base_a, input_x_array[index], top_w, bn_ctx);
    
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
    out_inv = BN_new();
    out_gcd = BN_new();

    /* Calculate the number of limbs (top_w) corresponding to our target bit length */
    top_w = (BIT_LENGTH + BN_BITS2 - 1) / BN_BITS2;
    
    /* Pre-expand the output containers to prevent triggering malloc within the timed section */
    bn_wexpand(out_inv, top_w);
    bn_wexpand(out_gcd, top_w);

    /* 1. Initialize data */
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

    printf("\nStarting FAIR dudect analysis for Constant-Time GCD/Inversion...\n");
    printf("Mode: %s\n", mode_str);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (int i = 0; i < 30; i++) {
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
    free(out_inv);
    free(out_gcd);
    BN_CTX_free(bn_ctx);

    return 0;
}