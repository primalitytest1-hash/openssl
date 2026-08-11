/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include "bn_local.h"

/*
 * The quick sieve algorithm approach to weeding out primes is Philip
 * Zimmermann's, as implemented in PGP.  I have had a read of his comments
 * and implemented my own version.
 */
#include "bn_prime.h"

static int probable_prime(BIGNUM *rnd, int bits, int safe, prime_t *mods,
    BN_CTX *ctx);
static int probable_prime_dh(BIGNUM *rnd, int bits, int safe, prime_t *mods,
    const BIGNUM *add, const BIGNUM *rem,
    BN_CTX *ctx);
static int bn_is_prime_int(const BIGNUM *w, int checks, BN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb);

#define square(x) ((BN_ULONG)(x) * (BN_ULONG)(x))

#if BN_BITS2 == 64
#define BN_DEF(lo, hi) (BN_ULONG)hi << 32 | lo
#else
#define BN_DEF(lo, hi) lo, hi
#endif

/*
 * See SP800 89 5.3.3 (Step f)
 * The product of the set of primes ranging from 3 to 751
 * Generated using process in test/bn_internal_test.c test_bn_small_factors().
 * This includes 751 (which is not currently included in SP 800-89).
 */
static const BN_ULONG small_prime_factors[] = {
    BN_DEF(0x3ef4e3e1, 0xc4309333), BN_DEF(0xcd2d655f, 0x71161eb6),
    BN_DEF(0x0bf94862, 0x95e2238c), BN_DEF(0x24f7912b, 0x3eb233d3),
    BN_DEF(0xbf26c483, 0x6b55514b), BN_DEF(0x5a144871, 0x0a84d817),
    BN_DEF(0x9b82210a, 0x77d12fee), BN_DEF(0x97f050b3, 0xdb5b93c2),
    BN_DEF(0x4d6c026b, 0x4acad6b9), BN_DEF(0x54aec893, 0xeb7751f3),
    BN_DEF(0x36bc85c4, 0xdba53368), BN_DEF(0x7f5ec78e, 0xd85a1b28),
    BN_DEF(0x6b322244, 0x2eb072d8), BN_DEF(0x5e2b3aea, 0xbba51112),
    BN_DEF(0x0e2486bf, 0x36ed1a6c), BN_DEF(0xec0c5727, 0x5f270460),
    (BN_ULONG)0x000017b1
};

#define BN_SMALL_PRIME_FACTORS_TOP OSSL_NELEM(small_prime_factors)
static const BIGNUM _bignum_small_prime_factors = {
    (BN_ULONG *)small_prime_factors,
    BN_SMALL_PRIME_FACTORS_TOP,
    BN_SMALL_PRIME_FACTORS_TOP,
    0,
    BN_FLG_STATIC_DATA
};

const BIGNUM *ossl_bn_get0_small_factors(void)
{
    return &_bignum_small_prime_factors;
}

/*
 * Calculate the number of trial divisions that gives the best speed in
 * combination with Miller-Rabin prime test, based on the sized of the prime.
 */
static int calc_trial_divisions(int bits)
{
    if (bits <= 512)
        return 64;
    else if (bits <= 1024)
        return 128;
    else if (bits <= 2048)
        return 384;
    else if (bits <= 4096)
        return 1024;
    return NUMPRIMES;
}

/*
 * Use a minimum of 64 rounds of Miller-Rabin, which should give a false
 * positive rate of 2^-128. If the size of the prime is larger than 2048
 * the user probably wants a higher security level than 128, so switch
 * to 128 rounds giving a false positive rate of 2^-256.
 * Returns the number of rounds.
 */
static int bn_mr_min_checks(int bits)
{
    if (bits > 2048)
        return 128;
    return 64;
}

int BN_GENCB_call(BN_GENCB *cb, int a, int b)
{
    /* No callback means continue */
    if (!cb)
        return 1;
    switch (cb->ver) {
    case 1:
        /* Deprecated-style callbacks */
        if (!cb->cb.cb_1)
            return 1;
        cb->cb.cb_1(a, b, cb->arg);
        return 1;
    case 2:
        /* New-style callbacks */
        return cb->cb.cb_2(a, b, cb);
    default:
        break;
    }
    /* Unrecognised callback type */
    return 0;
}

int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb,
    BN_CTX *ctx)
{
    BIGNUM *t;
    int found = 0;
    int i, j, c1 = 0;
    prime_t *mods = NULL;
    int checks = bn_mr_min_checks(bits);

    if (bits < 2) {
        /* There are no prime numbers this small. */
        ERR_raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL);
        return 0;
    } else if (add == NULL && safe && bits < 6 && bits != 3) {
        /*
         * The smallest safe prime (7) is three bits.
         * But the following two safe primes with less than 6 bits (11, 23)
         * are unreachable for BN_rand with BN_RAND_TOP_TWO.
         */
        ERR_raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL);
        return 0;
    }

    mods = OPENSSL_calloc(NUMPRIMES, sizeof(*mods));
    if (mods == NULL)
        return 0;

    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if (t == NULL)
        goto err;
loop:
    /* make a random number and set the top and bottom bits */
    if (add == NULL) {
        if (!probable_prime(ret, bits, safe, mods, ctx))
            goto err;
    } else {
        if (!probable_prime_dh(ret, bits, safe, mods, add, rem, ctx))
            goto err;
    }

    if (!BN_GENCB_call(cb, 0, c1++))
        /* aborted */
        goto err;

    if (!safe) {
        i = bn_is_prime_int(ret, checks, ctx, 0, cb);
        if (i == -1)
            goto err;
        if (i == 0)
            goto loop;
    } else {
        /*
         * for "safe prime" generation, check that (p-1)/2 is prime. Since a
         * prime is odd, We just need to divide by 2
         */
        if (!BN_rshift1(t, ret))
            goto err;

        for (i = 0; i < checks; i++) {
            j = bn_is_prime_int(ret, 1, ctx, 0, cb);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            j = bn_is_prime_int(t, 1, ctx, 0, cb);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            if (!BN_GENCB_call(cb, 2, c1 - 1))
                goto err;
            /* We have a safe prime test pass */
        }
    }
    /* we have a prime :-) */
    found = 1;
err:
    OPENSSL_free(mods);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return found;
}

#ifndef FIPS_MODULE
int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
{
    BN_CTX *ctx = BN_CTX_new();
    int retval;

    if (ctx == NULL)
        return 0;

    retval = BN_generate_prime_ex2(ret, bits, safe, add, rem, cb, ctx);

    BN_CTX_free(ctx);
    return retval;
}
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
    BN_GENCB *cb)
{
    return ossl_bn_check_prime(a, checks, ctx_passed, 0, cb);
}

int BN_is_prime_fasttest_ex(const BIGNUM *w, int checks, BN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb)
{
    return ossl_bn_check_prime(w, checks, ctx, do_trial_division, cb);
}
#endif

/* Wrapper around bn_is_prime_int that sets the minimum number of checks */
int ossl_bn_check_prime(const BIGNUM *w, int checks, BN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb)
{
    int min_checks = bn_mr_min_checks(BN_num_bits(w));

    if (checks < min_checks)
        checks = min_checks;

    return bn_is_prime_int(w, checks, ctx, do_trial_division, cb);
}

/*
 * Use this only for key generation.
 * It always uses trial division. The number of checks
 * (MR rounds) passed in is used without being clamped to a minimum value.
 */
int ossl_bn_check_generated_prime(const BIGNUM *w, int checks, BN_CTX *ctx,
    BN_GENCB *cb)
{
    return bn_is_prime_int(w, checks, ctx, 1, cb);
}

int BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb)
{
    return ossl_bn_check_prime(p, 0, ctx, 1, cb);
}

/*
 * Tests that |w| is probably prime
 * See FIPS 186-4 C.3.1 Miller Rabin Probabilistic Primality Test.
 *
 * Returns 0 when composite, 1 when probable prime, -1 on error.
 */
static int bn_is_prime_int(const BIGNUM *w, int checks, BN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb)
{
    int i, status, ret = -1;
#ifndef FIPS_MODULE
    BN_CTX *ctxlocal = NULL;
#else

    if (ctx == NULL)
        return -1;
#endif

    /* w must be bigger than 1 */
    if (BN_cmp(w, BN_value_one()) <= 0)
        return 0;

    /* w must be odd */
    if (BN_is_odd(w)) {
        /* Take care of the really small prime 3 */
        if (BN_is_word(w, 3))
            return 1;
    } else {
        /* 2 is the only even prime */
        return BN_is_word(w, 2);
    }

    /* first look for small factors */
    if (do_trial_division) {
        int trial_divisions = calc_trial_divisions(BN_num_bits(w));

        for (i = 1; i < trial_divisions; i++) {
            BN_ULONG mod = BN_mod_word(w, primes[i]);
            if (mod == (BN_ULONG)-1)
                return -1;
            if (mod == 0)
                return BN_is_word(w, primes[i]);
        }
        if (!BN_GENCB_call(cb, 1, -1))
            return -1;
    }
#ifndef FIPS_MODULE
    if (ctx == NULL && (ctxlocal = ctx = BN_CTX_new()) == NULL)
        goto err;
#endif

    if (!ossl_bn_miller_rabin_is_prime(w, checks, ctx, cb, 0, &status)) {
        ret = -1;
        goto err;
    }
    ret = (status == BN_PRIMETEST_PROBABLY_PRIME);
err:
#ifndef FIPS_MODULE
    BN_CTX_free(ctxlocal);
#endif
    return ret;
}

/*
 * Refer to FIPS 186-4 C.3.2 Enhanced Miller-Rabin Probabilistic Primality Test.
 * OR C.3.1 Miller-Rabin Probabilistic Primality Test (if enhanced is zero).
 * The Step numbers listed in the code refer to the enhanced case.
 *
 * if enhanced is set, then status returns one of the following:
 *     BN_PRIMETEST_PROBABLY_PRIME
 *     BN_PRIMETEST_COMPOSITE_WITH_FACTOR
 *     BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME
 * if enhanced is zero, then status returns either
 *     BN_PRIMETEST_PROBABLY_PRIME or
 *     BN_PRIMETEST_COMPOSITE
 *
 * returns 0 if there was an error, otherwise it returns 1.
 */
int ossl_bn_miller_rabin_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
    BN_GENCB *cb, int enhanced, int *status)
{
    int i, j, a, ret = 0;
    BIGNUM *g, *w1, *w3, *x, *m, *z, *b;
    BN_MONT_CTX *mont = NULL;

    /* w must be odd */
    if (!BN_is_odd(w))
        return 0;

    BN_CTX_start(ctx);
    g = BN_CTX_get(ctx);
    w1 = BN_CTX_get(ctx);
    w3 = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);

    if (!(b != NULL
            /* w1 := w - 1 */
            && BN_copy(w1, w)
            && BN_sub_word(w1, 1)
            /* w3 := w - 3 */
            && BN_copy(w3, w)
            && BN_sub_word(w3, 3)))
        goto err;

    /* check w is larger than 3, otherwise the random b will be too small */
    if (BN_is_zero(w3) || BN_is_negative(w3))
        goto err;

    /* (Step 1) Calculate largest integer 'a' such that 2^a divides w-1 */
    a = 1;
    while (!BN_is_bit_set(w1, a))
        a++;
    /* (Step 2) m = (w-1) / 2^a */
    if (!BN_rshift(m, w1, a))
        goto err;

    /* Montgomery setup for computations mod a */
    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w, ctx))
        goto err;

    if (iterations == 0)
        iterations = bn_mr_min_checks(BN_num_bits(w));

    /* (Step 4) */
    for (i = 0; i < iterations; ++i) {
        /* (Step 4.1) obtain a Random string of bits b where 1 < b < w-1 */
        if (!BN_priv_rand_range_ex(b, w3, 0, ctx)
            || !BN_add_word(b, 2)) /* 1 < b < w-1 */
            goto err;

        if (enhanced) {
            /* (Step 4.3) */
            if (!BN_gcd(g, b, w, ctx))
                goto err;
            /* (Step 4.4) */
            if (!BN_is_one(g)) {
                *status = BN_PRIMETEST_COMPOSITE_WITH_FACTOR;
                ret = 1;
                goto err;
            }
        }
        /* (Step 4.5) z = b^m mod w */
        if (!BN_mod_exp_mont(z, b, m, w, ctx, mont))
            goto err;
        /* (Step 4.6) if (z = 1 or z = w-1) */
        if (BN_is_one(z) || BN_cmp(z, w1) == 0)
            goto outer_loop;
        /* (Step 4.7) for j = 1 to a-1 */
        for (j = 1; j < a; ++j) {
            /* (Step 4.7.1 - 4.7.2) x = z. z = x^2 mod w */
            if (!BN_copy(x, z) || !BN_mod_mul(z, x, x, w, ctx))
                goto err;
            /* (Step 4.7.3) */
            if (BN_cmp(z, w1) == 0)
                goto outer_loop;
            /* (Step 4.7.4) */
            if (BN_is_one(z))
                goto composite;
        }
        /* At this point z = b^((w-1)/2) mod w */
        /* (Steps 4.8 - 4.9) x = z, z = x^2 mod w */
        if (!BN_copy(x, z) || !BN_mod_mul(z, x, x, w, ctx))
            goto err;
        /* (Step 4.10) */
        if (BN_is_one(z))
            goto composite;
        /* (Step 4.11) x = b^(w-1) mod w */
        if (!BN_copy(x, z))
            goto err;
    composite:
        if (enhanced) {
            /* (Step 4.1.2) g = GCD(x-1, w) */
            if (!BN_sub_word(x, 1) || !BN_gcd(g, x, w, ctx))
                goto err;
            /* (Steps 4.1.3 - 4.1.4) */
            if (BN_is_one(g))
                *status = BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME;
            else
                *status = BN_PRIMETEST_COMPOSITE_WITH_FACTOR;
        } else {
            *status = BN_PRIMETEST_COMPOSITE;
        }
        ret = 1;
        goto err;
    outer_loop:;
        /* (Step 4.1.5) */
        if (!BN_GENCB_call(cb, 1, i))
            goto err;
    }
    /* (Step 5) */
    *status = BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;
err:
    BN_clear(g);
    BN_clear(w1);
    BN_clear(w3);
    BN_clear(x);
    BN_clear(m);
    BN_clear(z);
    BN_clear(b);
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

/*
 * Generate a random number of |bits| bits that is probably prime by sieving.
 * If |safe| != 0, it generates a safe prime.
 * |mods| is a preallocated array that gets reused when called again.
 *
 * The probably prime is saved in |rnd|.
 *
 * Returns 1 on success and 0 on error.
 */
static int probable_prime(BIGNUM *rnd, int bits, int safe, prime_t *mods,
    BN_CTX *ctx)
{
    int i;
    BN_ULONG delta;
    int trial_divisions = calc_trial_divisions(bits);
    BN_ULONG maxdelta = BN_MASK2 - primes[trial_divisions - 1];

again:
    if (!BN_priv_rand_ex(rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0,
            ctx))
        return 0;
    if (safe && !BN_set_bit(rnd, 1))
        return 0;
    /* we now have a random number 'rnd' to test. */
    for (i = 1; i < trial_divisions; i++) {
        BN_ULONG mod = BN_mod_word(rnd, (BN_ULONG)primes[i]);
        if (mod == (BN_ULONG)-1)
            return 0;
        mods[i] = (prime_t)mod;
    }
    delta = 0;
loop:
    for (i = 1; i < trial_divisions; i++) {
        /*
         * check that rnd is a prime and also that
         * gcd(rnd-1,primes) == 1 (except for 2)
         * do the second check only if we are interested in safe primes
         * in the case that the candidate prime is a single word then
         * we check only the primes up to sqrt(rnd)
         */
        if (bits <= 31 && delta <= 0x7fffffff
            && square(primes[i]) > BN_get_word(rnd) + delta)
            break;
        if (safe ? (mods[i] + delta) % primes[i] <= 1
                 : (mods[i] + delta) % primes[i] == 0) {
            delta += safe ? 4 : 2;
            if (delta > maxdelta)
                goto again;
            goto loop;
        }
    }
    if (!BN_add_word(rnd, delta))
        return 0;
    if (BN_num_bits(rnd) != bits)
        goto again;
    bn_check_top(rnd);
    return 1;
}

/*
 * Generate a random number |rnd| of |bits| bits that is probably prime
 * and satisfies |rnd| % |add| == |rem| by sieving.
 * If |safe| != 0, it generates a safe prime.
 * |mods| is a preallocated array that gets reused when called again.
 *
 * Returns 1 on success and 0 on error.
 */
static int probable_prime_dh(BIGNUM *rnd, int bits, int safe, prime_t *mods,
    const BIGNUM *add, const BIGNUM *rem,
    BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *t1;
    BN_ULONG delta;
    int trial_divisions = calc_trial_divisions(bits);
    BN_ULONG maxdelta = BN_MASK2 - primes[trial_divisions - 1];

    BN_CTX_start(ctx);
    if ((t1 = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (maxdelta > BN_MASK2 - BN_get_word(add))
        maxdelta = BN_MASK2 - BN_get_word(add);

again:
    if (!BN_rand_ex(rnd, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx))
        goto err;

    /* we need ((rnd-rem) % add) == 0 */

    if (!BN_mod(t1, rnd, add, ctx))
        goto err;
    if (!BN_sub(rnd, rnd, t1))
        goto err;
    if (rem == NULL) {
        if (!BN_add_word(rnd, safe ? 3u : 1u))
            goto err;
    } else {
        if (!BN_add(rnd, rnd, rem))
            goto err;
    }

    if (BN_num_bits(rnd) < bits
        || BN_get_word(rnd) < (safe ? 5u : 3u)) {
        if (!BN_add(rnd, rnd, add))
            goto err;
    }

    /* we now have a random number 'rnd' to test. */
    for (i = 1; i < trial_divisions; i++) {
        BN_ULONG mod = BN_mod_word(rnd, (BN_ULONG)primes[i]);
        if (mod == (BN_ULONG)-1)
            goto err;
        mods[i] = (prime_t)mod;
    }
    delta = 0;
loop:
    for (i = 1; i < trial_divisions; i++) {
        /* check that rnd is a prime */
        if (bits <= 31 && delta <= 0x7fffffff
            && square(primes[i]) > BN_get_word(rnd) + delta)
            break;
        /* rnd mod p == 1 implies q = (rnd-1)/2 is divisible by p */
        if (safe ? (mods[i] + delta) % primes[i] <= 1
                 : (mods[i] + delta) % primes[i] == 0) {
            delta += BN_get_word(add);
            if (delta > maxdelta)
                goto again;
            goto loop;
        }
    }
    if (!BN_add_word(rnd, delta))
        goto err;
    ret = 1;

err:
    BN_CTX_end(ctx);
    bn_check_top(rnd);
    return ret;
}


/* ====================================================================
 * 1. Constant-Time Auxiliary Functions (Integer Level)
 * ==================================================================== */

/* Returns 1 if val >= 0, otherwise 0 (for 2's complement signed integers) */
static inline int64_t ct_is_ge_zero(int64_t val) {
    return (int64_t)(((uint64_t)val >> 63) ^ 1);
}

/* Checks if uint64_t is non-zero: returns 1 if v > 0, returns 0 if v == 0 */
static inline int64_t ct_is_nz_u64(uint64_t v) {
    return (int64_t)((v | (~v + 1)) >> 63) & 1;
}

/* Returns an all-1 mask (0xFF...F) if bit is 1, returns 0 if bit is 0 */
static inline int64_t ct_mask_64(int64_t bit) {
    return -(bit & 1);
}

/* Constant-time select: chooses a or b based on the mask */
static inline int64_t ct_select_64(int64_t mask, int64_t a, int64_t b) {
    return (mask & a) | (~mask & b);
}

/* Branchless implementation of arithmetic right shift by 1 bit (Floor division) */
static inline int64_t ct_asr_1(int64_t val) {
    int64_t mask = ct_mask_64(val < 0);
    return ct_select_64(mask, ~((~val) >> 1), val >> 1);
}

/* Constant-time equality (returns 1 if a == b, otherwise returns 0) */
static int ct_eq_int(int a, int b) {
    unsigned int diff = (unsigned int)(a ^ b);
    return (int)(1 - ((diff | (~diff + 1)) >> 31));
}

/* Constant-time greater than or equal (returns 1 if a >= b, otherwise returns 0) */
static int ct_ge_int(int a, int b) {
    return (int)(1 - (((unsigned int)(a - b)) >> 31)); 
}

/* ====================================================================
 * 2. Fixed-Length BIGNUM (CT_BIGNUM) Configuration
 * ==================================================================== */
#define INPUT_LIMBS 32 
#define WORK_LIMBS (INPUT_LIMBS + 2)

static void ct_bn_cond_negate(uint64_t *x, int64_t mask) {
    uint64_t carry = mask & 1;
    for (int i = 0; i < WORK_LIMBS; i++) {
        uint64_t inv = x[i] ^ mask;
        x[i] = inv + carry;
        carry = (x[i] < inv) ? 1 : 0;
    }
}

static void ct_bn_from_openssl(uint64_t *out, const BIGNUM *in) {
    unsigned char buf[INPUT_LIMBS * 8];
    memset(buf, 0, sizeof(buf));
    
    BN_bn2lebinpad(in, buf, sizeof(buf)); 
    
    for (int i = 0; i < INPUT_LIMBS; i++) {
        uint64_t limb = 0;
        for(int j = 0; j < 8; j++) {
            limb |= ((uint64_t)buf[i * 8 + j]) << (j * 8);
        }
        out[i] = limb;
    }
    for (int i = INPUT_LIMBS; i < WORK_LIMBS; i++) out[i] = 0;
    
    if (BN_is_negative(in)) {
        ct_bn_cond_negate(out, -1);
    }
}

static void ct_bn_add(uint64_t *res, const uint64_t *a, const uint64_t *b) {
    uint64_t carry = 0;
    for (int i = 0; i < WORK_LIMBS; i++) {
        uint64_t sum1 = a[i] + b[i];
        uint64_t c1 = (sum1 < a[i]) ? 1 : 0;
        res[i] = sum1 + carry;
        uint64_t c2 = (res[i] < sum1) ? 1 : 0;
        carry = c1 | c2;
    }
}

static void ct_bn_mul_signed(uint64_t *out, const uint64_t *in, int64_t multiplier) {
    int64_t mask_neg = ct_mask_64(multiplier < 0);
    uint64_t abs_m = (uint64_t)ct_select_64(mask_neg, -multiplier, multiplier);
    
    uint64_t temp[WORK_LIMBS];
    for (int i = 0; i < WORK_LIMBS; i++) temp[i] = in[i];
    
    ct_bn_cond_negate(temp, mask_neg);
    
    uint64_t carry = 0;
    for (int i = 0; i < WORK_LIMBS; i++) {
        unsigned __int128 p = (unsigned __int128)temp[i] * abs_m + carry;
        out[i] = (uint64_t)p;
        carry = (uint64_t)(p >> 64);
    }
}

static void ct_bn_rshift(uint64_t *x, int shift) {
    if (shift == 0) return;
    uint64_t sign_ext = ((int64_t)x[WORK_LIMBS - 1] < 0) ? (~0ULL << (64 - shift)) : 0;
    
    for (int i = 0; i < WORK_LIMBS - 1; i++) {
        x[i] = (x[i] >> shift) | (x[i + 1] << (64 - shift));
    }
    x[WORK_LIMBS - 1] = (x[WORK_LIMBS - 1] >> shift) | sign_ext;
}

static void batch_matrix(int64_t *x_io, int64_t *y_io, int64_t *delta_io, int batch,
                         int64_t *a_out, int64_t *b_out, int64_t *c_out, int64_t *d_out, 
                         uint64_t *u_acc) {
    int64_t a = 1, b = 0, c = 0, d = 1;
    int64_t x = *x_io, y = *y_io, delta = *delta_io;
    uint64_t u = 0;
    
    for (int i = 0; i < batch; i++) {
        int64_t yi = y;
        int64_t mask_swap = ct_mask_64(ct_is_ge_zero(delta) & (x & 1));
        int64_t mask_odd  = ct_mask_64(x & 1);

        delta = ct_select_64(mask_swap, -delta, 1 + delta);

        int64_t operand_y = ct_select_64(mask_swap, -y, ct_select_64(mask_odd, y, 0));
        int64_t next_y    = ct_select_64(mask_swap, x, y);
        x = ct_asr_1(x + operand_y);
        y = next_y;

        int64_t next_a = ct_select_64(mask_swap, a - c, ct_select_64(mask_odd, a + c, a));
        int64_t next_b = ct_select_64(mask_swap, b - d, ct_select_64(mask_odd, b + d, b));
        int64_t next_ci = ct_select_64(mask_swap, 2 * a, 2 * c);
        int64_t next_di = ct_select_64(mask_swap, 2 * b, 2 * d);

        a = next_a; b = next_b; c = next_ci; d = next_di;

        uint64_t u_y = (uint64_t)y;
        u += (((uint64_t)yi & u_y) ^ (uint64_t)ct_asr_1((int64_t)u_y)) & 2;
        u += (u & 1) ^ (c < 0 ? 1 : 0);
        u %= 4;
    }
    
    *x_io = x; *y_io = y; *delta_io = delta;
    *a_out = a; *b_out = b; *c_out = c; *d_out = d;
    *u_acc = u;
}

/* ====================================================================
 * 3. Internal Hardware-level Constant-Time Helpers
 * ==================================================================== */

static void ct_pad_top(BIGNUM *a, int target_top) {
    int curr = a->top;
    for (int i = 0; i < target_top; i++) {
        BN_ULONG mask = (BN_ULONG)0 - (BN_ULONG)(i < curr);
        a->d[i] &= mask;
    }
    a->top = target_top; 
}

static int ct_bn_is_zero(const BIGNUM *a, int target_top) {
    BN_ULONG acc = 0;
    for (int k = 0; k < target_top; k++) {
        acc |= a->d[k];
    }
    return (acc == 0);
}

static void ct_swap_arrays(int swap, BIGNUM *A, BIGNUM *B, int top_w) {
    BN_ULONG mask = 0 - (BN_ULONG)swap;
    for (int i = 0; i < top_w; i++) {
        BN_ULONG tmp = (A->d[i] ^ B->d[i]) & mask;
        A->d[i] ^= tmp;
        B->d[i] ^= tmp;
    }
}

static void ct_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, int top_w, BIGNUM *tmp) {
    BN_ULONG carry = bn_add_words(r->d, a->d, b->d, top_w);
    r->top = top_w; r->neg = 0;
    BN_ULONG borrow = bn_sub_words(tmp->d, r->d, m->d, top_w);
    tmp->top = top_w; tmp->neg = 0;
    ct_swap_arrays(carry | (1 - borrow), r, tmp, top_w);
}

static void ct_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, int top_w, BIGNUM *tmp) {
    BN_ULONG borrow = bn_sub_words(r->d, a->d, b->d, top_w);
    r->top = top_w; r->neg = 0;
    (void)bn_add_words(tmp->d, r->d, m->d, top_w);
    tmp->top = top_w; tmp->neg = 0;
    ct_swap_arrays(borrow, r, tmp, top_w);
}

static void ct_bn_copy(BIGNUM *dst, const BIGNUM *src, int top_w) {
    for (int i = 0; i < top_w; i++) dst->d[i] = src->d[i];
    dst->top = top_w; dst->neg = 0;
}

static void ct_bn_copy_padded(BIGNUM *dst, const BIGNUM *src, int top_w) {
    for (int i = 0; i < top_w; i++) {
        dst->d[i] = (i < src->top) ? src->d[i] : 0;
    }
    dst->top = top_w; dst->neg = 0;
}

static void ct_bn_rshift1(BIGNUM *a, int top_w) {
    BN_ULONG carry = 0;
    for (int i = top_w - 1; i >= 0; i--) {
        BN_ULONG next_carry = (a->d[i] & 1) << (BN_BITS2 - 1);
        a->d[i] = (a->d[i] >> 1) | carry;
        carry = next_carry;
    }
    a->top = top_w;
}

static void ct_bn_add_word(BIGNUM *a, BN_ULONG w, int top_w) {
    BN_ULONG c = w;
    for (int i = 0; i < top_w; i++) {
        BN_ULONG sum = a->d[i] + c;
        c = (sum < a->d[i]) ? 1 : 0;
        a->d[i] = sum;
    }
    a->top = top_w;
}

static void ct_mont_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BN_MONT_CTX *mont, int top_w, BIGNUM *tmp) {
    bn_mul_mont(tmp->d, a->d, b->d, mont->N.d, mont->n0, top_w);
    ct_bn_copy(r, tmp, top_w);
}

/* Constant-time BIGNUM equality check (Pure XOR compression, replaces heavy ct_mod_sub).
 * Guarantees execution time depends only on top length, completely independent of value content.
 */
static int ct_bn_equal(const BIGNUM *a, const BIGNUM *b, int top) {
    BN_ULONG diff = 0;
    for (int k = 0; k < top; k++) {
        diff |= (a->d[k] ^ b->d[k]); 
    }
    return (int)(1 - ((diff | (~diff + 1)) >> (BN_BITS2 - 1)));
}

/* ====================================================================
 * 4. Complex Constant-Time Math Operations
 * ==================================================================== */

/* Constant-Time algorithm supporting both GCD and modular inversion */
void ct_by_gcd_inv(BIGNUM *out_inv, BIGNUM *out_gcd, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *A = BN_CTX_get(ctx); bn_wexpand(A, top_w); ct_pad_top(A, top_w);
    BIGNUM *B = BN_CTX_get(ctx); bn_wexpand(B, top_w); ct_pad_top(B, top_w);
    BIGNUM *U = BN_CTX_get(ctx); bn_wexpand(U, top_w); ct_pad_top(U, top_w);
    BIGNUM *V = BN_CTX_get(ctx); bn_wexpand(V, top_w); ct_pad_top(V, top_w);
    BIGNUM *tmp1 = BN_CTX_get(ctx); bn_wexpand(tmp1, top_w); ct_pad_top(tmp1, top_w);
    BIGNUM *tmp2 = BN_CTX_get(ctx); bn_wexpand(tmp2, top_w); ct_pad_top(tmp2, top_w);
    
    ct_bn_copy_padded(A, m, top_w);
    ct_bn_copy_padded(B, x, top_w);
    BN_zero(U); ct_pad_top(U, top_w);
    BN_one(V); ct_pad_top(V, top_w);
    
    int iters = 3 * top_w * BN_BITS2;
    
    for (int i = 0; i < iters; i++) {
        int B_is_odd = B->d[0] & 1;
        
        BN_ULONG borrow = bn_sub_words(tmp1->d, A->d, B->d, top_w);
        int swap = B_is_odd & (1 - (int)borrow);
        
        ct_swap_arrays(swap, A, B, top_w);
        ct_swap_arrays(swap, U, V, top_w);
        
        bn_sub_words(tmp1->d, B->d, A->d, top_w);
        ct_swap_arrays(B_is_odd, B, tmp1, top_w);
        
        ct_mod_sub(tmp2, V, U, m, top_w, tmp1);
        ct_swap_arrays(B_is_odd, V, tmp2, top_w);
        
        ct_bn_rshift1(B, top_w);
        
        int V_is_odd = V->d[0] & 1;
        BN_ULONG carry = bn_add_words(tmp1->d, V->d, m->d, top_w);
        for (int j = 0; j < top_w - 1; j++) {
            tmp1->d[j] = (tmp1->d[j] >> 1) | ((tmp1->d[j+1] & 1) << (BN_BITS2 - 1));
        }
        tmp1->d[top_w - 1] = (tmp1->d[top_w - 1] >> 1) | (carry << (BN_BITS2 - 1));
        tmp1->top = top_w; tmp1->neg = 0;
        
        ct_bn_rshift1(V, top_w);
        ct_swap_arrays(V_is_odd, V, tmp1, top_w);
    }
    
    if (out_inv) ct_bn_copy(out_inv, U, top_w);
    if (out_gcd) ct_bn_copy(out_gcd, A, top_w);
    BN_CTX_end(ctx);
}

/* Wrapper dedicated for Lucas Test (retrieves inverse only) */
void ct_by_invert(BIGNUM *out, const BIGNUM *x, const BIGNUM *m, int top_w, BN_CTX *ctx) {
    ct_by_gcd_inv(out, NULL, x, m, top_w, ctx);
}

/* Original bn_mod_exp_mont_ladder (used by tests like Miller-Rabin) */
static int bn_mod_exp_mont_ladder(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                  const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *mont) {
    BIGNUM *R0, *R1, *t1;
    int i, bit;
    int top_m = m->top;
    
    BN_CTX_start(ctx);
    R0 = BN_CTX_get(ctx);
    R1 = BN_CTX_get(ctx);
    t1 = BN_CTX_get(ctx);
    
    BN_one(R0);
    BN_to_montgomery(R0, R0, mont, ctx);
    BN_to_montgomery(R1, a, mont, ctx);
    
    bn_wexpand(R0, top_m); ct_pad_top(R0, top_m);
    bn_wexpand(R1, top_m); ct_pad_top(R1, top_m);
    bn_wexpand(t1, top_m); ct_pad_top(t1, top_m);
    
    for (i = BN_num_bits(p) - 1; i >= 0; i--) {
        bit = BN_is_bit_set(p, i);
        
        ct_pad_top(R0, top_m); ct_pad_top(R1, top_m);
        ct_swap_arrays(bit, R0, R1, top_m);
        
        BN_mod_mul_montgomery(t1, R0, R1, mont, ctx); 
        BN_mod_mul_montgomery(R0, R0, R0, mont, ctx); 
        BN_copy(R1, t1);                              
        
        ct_pad_top(R0, top_m); ct_pad_top(R1, top_m);
        ct_swap_arrays(bit, R0, R1, top_m);
    }
    
    BN_from_montgomery(r, R0, mont, ctx);
    BN_CTX_end(ctx);
    return 1;
}

static int ct_mod_exp_mont_ladder(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, 
                                  const BN_MONT_CTX *mont, int top_w, BN_CTX *ctx, 
                                  BIGNUM *plain_one, BIGNUM *ct_tmp) {
    BN_CTX_start(ctx);
    BIGNUM *R0 = BN_CTX_get(ctx); bn_wexpand(R0, top_w); ct_pad_top(R0, top_w);
    BIGNUM *R1 = BN_CTX_get(ctx); bn_wexpand(R1, top_w); ct_pad_top(R1, top_w);
    
    ct_mont_mul(R0, plain_one, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(R1, a, &(mont->RR), mont, top_w, ct_tmp);
    
    /* Note: The loop count depends on bit length, but since p is the public w_minus_1, length leakage is safe */
    int p_bits = BN_num_bits(p); 
    for (int i = p_bits - 1; i >= 0; i--) {
        int word_idx = i / BN_BITS2;
        int bit_idx = i % BN_BITS2;
        int bit = (int)((p->d[word_idx] >> bit_idx) & 1);
        
        ct_swap_arrays(bit, R0, R1, top_w);
        
        ct_mont_mul(R1, R0, R1, mont, top_w, ct_tmp); 
        ct_mont_mul(R0, R0, R0, mont, top_w, ct_tmp); 
        
        ct_swap_arrays(bit, R0, R1, top_w);
    }
    
    ct_mont_mul(r, R0, plain_one, mont, top_w, ct_tmp);
    BN_CTX_end(ctx);
    return 1;
}

static void ct_set_to_one_if(BIGNUM *x, int set, int top_w)
{
    BN_ULONG mask = 0 - (BN_ULONG)set;

    for (int i = 0; i < top_w; i++) {
        BN_ULONG target = (i == 0) ? 1 : 0;
        x->d[i] = (x->d[i] & ~mask) | (target & mask);
    }

    x->top = top_w;
    x->neg = 0;
}

static int ct_batch_invert_mont(BIGNUM **X_inv, BIGNUM **X, int n, const BIGNUM *w, 
                                int top_w, BN_CTX *ctx, BN_MONT_CTX *mont, 
                                BIGNUM *plain_one, BIGNUM *ct_tmp, int *is_composite) 
{
    if (n <= 0) return 1;
    int ret = 0;
    BN_CTX_start(ctx);
    
    BIGNUM *I_all = BN_CTX_get(ctx);
    BIGNUM *X_mont = BN_CTX_get(ctx);
    BIGNUM **C = OPENSSL_malloc(n * sizeof(BIGNUM *)); 
    
    if (C == NULL || I_all == NULL || X_mont == NULL) goto end;
    
    if(!bn_wexpand(I_all, top_w))
        goto end;
    ct_pad_top(I_all, top_w);
    if(!bn_wexpand(X_mont, top_w))
        goto end;
    ct_pad_top(X_mont, top_w);

    for (int i = 0; i < n; i++) {
        C[i] = BN_CTX_get(ctx);
        if (C[i] == NULL) goto end;
        if (!bn_wexpand(C[i], top_w)) goto end; 
        ct_pad_top(C[i], top_w);
        
        int is_zero = ct_bn_is_zero(X[i], top_w);
        *is_composite |= is_zero;
        /* Replace zero denominator by 1 for dummy fixed-path computation. */
        ct_set_to_one_if(X[i], is_zero, top_w);
    }

    ct_mont_mul(C[0], X[0], &(mont->RR), mont, top_w, ct_tmp); 
    for (int i = 1; i < n; i++) {
        ct_mont_mul(X_mont, X[i], &(mont->RR), mont, top_w, ct_tmp);
        ct_mont_mul(C[i], C[i-1], X_mont, mont, top_w, ct_tmp); 
    }

    BIGNUM *total_gcd = BN_CTX_get(ctx);
    if (total_gcd == NULL)
        goto end;
    if (!bn_wexpand(total_gcd, top_w))
        goto end;
    ct_pad_top(total_gcd, top_w);

    ct_by_gcd_inv(I_all, total_gcd, C[n-1], w, top_w, ctx);

    int is_gcd_not_one = 1 - ct_bn_equal(total_gcd, plain_one, top_w);
    *is_composite |= is_gcd_not_one;

    for (int i = n - 1; i > 0; i--) {
        ct_mont_mul(X_inv[i], I_all, C[i-1], mont, top_w, ct_tmp);
        ct_mont_mul(X_inv[i], X_inv[i], &(mont->RR), mont, top_w, ct_tmp); 
        
        ct_mont_mul(X_mont, X[i], &(mont->RR), mont, top_w, ct_tmp);
        ct_mont_mul(I_all, I_all, X_mont, mont, top_w, ct_tmp);
    }
    ct_mont_mul(X_inv[0], I_all, &(mont->RR), mont, top_w, ct_tmp); 

    ret = 1;
end:
    if (C != NULL) OPENSSL_free(C);
    BN_CTX_end(ctx);
    return ret;
}

/* ====================================================================
 * 5. Primality Testing Algorithms
 * ==================================================================== */

/* Jacobi symbol: Hamburg */
int ossl_bn_jacobi_by(const BIGNUM *x_in, const BIGNUM *y_in, BN_CTX *ctx) {
    uint64_t ct_x[WORK_LIMBS], ct_y[WORK_LIMBS];
    
    ct_bn_from_openssl(ct_x, x_in);
    ct_bn_from_openssl(ct_y, y_in);

    uint64_t y_zero_acc = 0;
    for (int i = 0; i < WORK_LIMBS; i++) y_zero_acc |= ct_y[i];
    int64_t mask_initial_y_zero = ct_mask_64(ct_is_nz_u64(y_zero_acc) ^ 1);
    int64_t mask_initial_y_even = ct_mask_64((ct_y[0] & 1) ^ 1);

    int x_neg = BN_is_negative(x_in);
    int y_neg = BN_is_negative(y_in);
    
    /* Force x, y to be positive and compensate the sign to align with Safegcd and Kronecker symbol */
    if (x_neg) ct_bn_cond_negate(ct_x, -1);
    if (y_neg) ct_bn_cond_negate(ct_y, -1);

    /* After forcing positive, simply take the lowest bits to get the correct |y| % 4 */
    uint64_t abs_y_mod_4 = ct_y[0] & 3; 
    
    int sign_multiplier = 1;
    if (x_neg && y_neg) sign_multiplier = -1;
    if (x_neg && abs_y_mod_4 == 3) sign_multiplier = -sign_multiplier;

    /* Ensure enough iterations are run (2048-bit upper bound) */
    int max_bits = INPUT_LIMBS * 64; 
    int niters = (45907 * max_bits + 26313) / 19929;
    
    int64_t delta = 0; 
    uint64_t t = 0; 
    int batch = 60; 
    int num_loops = (niters + batch - 1) / batch + 2; 
    uint64_t mask = (1ULL << (batch + 2)) - 1; 

    for (int i = 0; i < num_loops; i++) {
        int64_t x_prime = (int64_t)(ct_x[0] & mask);
        int64_t y_prime = (int64_t)(ct_y[0] & mask);
        
        int64_t a_i, b_i, c_i, d_i;
        uint64_t u_acc = 0;

        batch_matrix(&x_prime, &y_prime, &delta, batch, &a_i, &b_i, &c_i, &d_i, &u_acc);

        uint64_t tx_a[WORK_LIMBS], ty_b[WORK_LIMBS];
        uint64_t tx_c[WORK_LIMBS], ty_d[WORK_LIMBS];

        ct_bn_mul_signed(tx_a, ct_x, a_i);
        ct_bn_mul_signed(ty_b, ct_y, b_i);
        ct_bn_add(tx_a, tx_a, ty_b);  

        ct_bn_mul_signed(tx_c, ct_x, c_i);
        ct_bn_mul_signed(ty_d, ct_y, d_i);
        ct_bn_add(tx_c, tx_c, ty_d);  

        ct_bn_rshift(tx_a, batch);
        ct_bn_rshift(tx_c, batch);
        
        for (int j = 0; j < WORK_LIMBS; j++) {
            ct_x[j] = tx_a[j];
            ct_y[j] = tx_c[j];
        }
        
        t = (t + u_acc) % 4;
        int y_sign = ((int64_t)ct_y[WORK_LIMBS - 1] < 0) ? 1 : 0;
        t = (t + ((t & 1) ^ y_sign)) % 4;
    }

    t = (t + (t & 1)) % 4;
    
    uint64_t final_y_abs[WORK_LIMBS];
    for (int i = 0; i < WORK_LIMBS; i++) final_y_abs[i] = ct_y[i];
    int64_t final_y_neg = ct_mask_64(((int64_t)ct_y[WORK_LIMBS - 1] < 0) ? 1 : 0);
    ct_bn_cond_negate(final_y_abs, final_y_neg); /* Take the absolute value of the result */

    uint64_t y_high_or = 0;
    for (int i = 1; i < WORK_LIMBS; i++) y_high_or |= final_y_abs[i];
    
    int64_t mask_y_high_zero = ct_mask_64(ct_is_nz_u64(y_high_or) ^ 1);
    int64_t mask_y_d0_one = ct_mask_64((final_y_abs[0] == 1) ? 1 : 0);
    int64_t mask_is_gcd_one = mask_y_high_zero & mask_y_d0_one; 
    
    int64_t mask_error = mask_initial_y_zero | mask_initial_y_even;
    int expected_jacobi = 1 - (int)t;
    int final_ret = (int)ct_select_64(mask_is_gcd_one, (int64_t)(sign_multiplier * expected_jacobi), 0);

    return (int)ct_select_64(mask_error, 0, final_ret);
}

/*
 * Constant-Time Near-Uniform Random Generator
 * Uses (L + 80) bit oversampling to make residual modulo bias negligible.
 */
static int ct_random_in_range(BIGNUM *out, const BIGNUM *n, BN_ULONG sub_from_n, BN_ULONG add_to_res, int top_w, BN_CTX *ctx) {
    int ret = 0;
    BIGNUM *M = NULL, *rand_bn = NULL, *R = NULL;
    BIGNUM *tmp_sub = NULL, *sub_bn = NULL, *add_bn = NULL, *pad_n = NULL;
    
    BN_CTX_start(ctx);
    M = BN_CTX_get(ctx); rand_bn = BN_CTX_get(ctx);
    R = BN_CTX_get(ctx); tmp_sub = BN_CTX_get(ctx);
    sub_bn = BN_CTX_get(ctx); add_bn = BN_CTX_get(ctx);
    pad_n = BN_CTX_get(ctx); 
    
    /* 【修正 2】：嚴格檢查記憶體分配，防止 OOM 導致崩潰 */
    if (pad_n == NULL) goto err;

    if (bn_wexpand(M, top_w) == NULL) goto err;
    if (bn_wexpand(R, top_w) == NULL) goto err;
    if (bn_wexpand(tmp_sub, top_w) == NULL) goto err;
    if (bn_wexpand(sub_bn, top_w) == NULL) goto err;
    if (bn_wexpand(add_bn, top_w) == NULL) goto err;
    if (bn_wexpand(out, top_w) == NULL) goto err;
    if (bn_wexpand(pad_n, top_w) == NULL) goto err;

    ct_pad_top(M, top_w);
    ct_pad_top(R, top_w);
    ct_pad_top(tmp_sub, top_w);
    ct_pad_top(sub_bn, top_w);
    ct_pad_top(add_bn, top_w);
    ct_pad_top(out, top_w);

    ct_bn_copy_padded(pad_n, n, top_w);

    /* Construct Modulus M = n - sub_from_n in Constant-Time */
    BN_zero(sub_bn); ct_pad_top(sub_bn, top_w);
    sub_bn->d[0] = sub_from_n;
    bn_sub_words(M->d, pad_n->d, sub_bn->d, top_w);
    M->top = top_w; M->neg = 0;
    
    int L = top_w * BN_BITS2; 
    int total_bits = L + 128;
    int rand_words = (total_bits + BN_BITS2 - 1) / BN_BITS2;
    
    if (bn_wexpand(rand_bn, rand_words) == NULL) goto err;
    if (!BN_priv_rand_ex(rand_bn, total_bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx)) goto err;
    ct_pad_top(rand_bn, rand_words);

    BN_zero(R); ct_pad_top(R, top_w);

    /* Constant-time bit-by-bit reduction: R = rand_bn % M */
    for (int i = total_bits - 1; i >= 0; i--) {
        int word_idx = i / BN_BITS2;
        int bit_idx = i % BN_BITS2;
        int bit_val = (int)((rand_bn->d[word_idx] >> bit_idx) & 1);
        
        /* R = 2 * R (Shift left by 1) */
        BN_ULONG carry = 0;
        for (int k = 0; k < top_w; k++) {
            BN_ULONG r_val = R->d[k];
            BN_ULONG new_val = (r_val << 1) | carry;
            carry = r_val >> (BN_BITS2 - 1);
            R->d[k] = new_val;
        }
        /* Add the extracted bit */
        R->d[0] |= bit_val;
        
        /* Conditional Subtraction: tmp_sub = R - M */
        BN_ULONG borrow = bn_sub_words(tmp_sub->d, R->d, M->d, top_w);
        int swap = (int)(carry | (1 - borrow));
        
        ct_swap_arrays(swap, R, tmp_sub, top_w);
    }

    /* out = R + add_to_res */
    BN_zero(add_bn); ct_pad_top(add_bn, top_w);
    add_bn->d[0] = add_to_res;
    bn_add_words(out->d, R->d, add_bn->d, top_w);
    out->top = top_w; out->neg = 0;

    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}


int ossl_bn_CHVL_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
                           BN_GENCB *cb, int *status)
{
    int i, j, bit, bit_len, ret = 0;
    BIGNUM *w1, *e, *D, *D_mont, *P, *mont_one, *mont_two, *w_minus_two, *c_mont;
    BIGNUM *R0_A, *R0_B, *R1_A, *R1_B;
    BIGNUM *m1, *m2, *m3, *tB1D, *temp_A, *temp_B, *tmp_prime, *ct_tmp, *plain_one, *plain_two;
    BN_MONT_CTX *mont = NULL;
    
    if (!BN_is_odd(w)) return 0;

    BN_CTX_start(ctx);
    
    w1 = BN_CTX_get(ctx); e = BN_CTX_get(ctx); 
    D = BN_CTX_get(ctx); D_mont = BN_CTX_get(ctx);
    P = BN_CTX_get(ctx); 
    mont_one = BN_CTX_get(ctx); mont_two = BN_CTX_get(ctx);
    w_minus_two = BN_CTX_get(ctx); c_mont = BN_CTX_get(ctx);
    R0_A = BN_CTX_get(ctx); R0_B = BN_CTX_get(ctx);
    R1_A = BN_CTX_get(ctx); R1_B = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx); m2 = BN_CTX_get(ctx); m3 = BN_CTX_get(ctx); 
    tB1D = BN_CTX_get(ctx); temp_A = BN_CTX_get(ctx); temp_B = BN_CTX_get(ctx);
    tmp_prime = BN_CTX_get(ctx); ct_tmp = BN_CTX_get(ctx); 
    plain_one = BN_CTX_get(ctx); plain_two = BN_CTX_get(ctx);

    if (plain_two == NULL) goto err;

    if (!BN_copy(w1, w)) goto err;
    BN_set_flags(w1, BN_FLG_CONSTTIME);

    int top_w = w1->top;

    BIGNUM *all_vars[] = {w1, e, D, D_mont, P, mont_one, mont_two, w_minus_two, c_mont,
                          R0_A, R0_B, R1_A, R1_B, m1, m2, m3, tB1D, temp_A, temp_B, tmp_prime, ct_tmp, plain_one, plain_two};
    for (int k = 0; k < 23; k++) {
        if (!bn_wexpand(all_vars[k], top_w)) goto err;
        ct_pad_top(all_vars[k], top_w);
    }

    /* ====================================================================
     * Phase 1: Parameter Setup & CFindD Algorithm
     * ==================================================================== */
    
    /* Algorithm CFindD Line 1: D <- 0, found <- false */
    int found_mask = 0;
    BN_zero(D); ct_pad_top(D, top_w);

    /* Algorithm CFindD Line 2-3: J_target <- CTSelect(is_3_mod_4, 1, -1) */
    int is_3_mod_4 = BN_is_bit_set(w, 1); 
    int target_j_val = is_3_mod_4 ? 1 : -1;

    static const int small_primes[40] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179
    };
    
    /* Algorithm CFindD Line 4: For p in L (strictly 40 iterations) */
    for (int k = 0; k < 40; k++) {
        BN_set_word(tmp_prime, small_primes[k]);
        ct_pad_top(tmp_prime, top_w);

        /* Algorithm CFindD Line 5: val <- ConstantTimeJacobi(p, n) */
        int j_val = ossl_bn_jacobi_by(tmp_prime, w, ctx); 
        
        /* Algorithm CFindD Lines 6-8: Conditionally update D */
        int is_match = (j_val == target_j_val);
        int update = is_match & (!found_mask);
        
        ct_swap_arrays(update, D, tmp_prime, top_w);
        found_mask |= update;
    }

    /* Algorithm CHVL Line 2: is_composite <- ~success */
    int is_composite = (1 - found_mask);

    /* Algorithm CHVL Lines 4-5: e <- (n + modifier) / 2 */
    ct_bn_copy_padded(e, w1, top_w);
    ct_bn_rshift1(e, top_w);
    ct_bn_add_word(e, 1 - (int)is_3_mod_4, top_w);
    
    bit_len = BN_num_bits(w1) - 1; 

    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w1, ctx)) goto err;
    
    BN_one(plain_one); ct_pad_top(plain_one, top_w);
    BN_set_word(plain_two, 2); ct_pad_top(plain_two, top_w);

    ct_mont_mul(D_mont, D, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_one, plain_one, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_two, plain_two, &(mont->RR), mont, top_w, ct_tmp);
    
    ct_mod_sub(w_minus_two, w1, plain_two, w1, top_w, ct_tmp);
    
    /* Dynamic split of iterations: Max 6 for Strong Lucas (ILPBP), rest for V-set (IVset) */
    const int NUM_STRONG_TESTS = 6;
    int strong_iters = (iterations < NUM_STRONG_TESTS) ? iterations : NUM_STRONG_TESTS;

    /* ====================================================================
     * Phase 3: Constant-Time Extension Ring Ladder (ILPBP Iterations)
     * Note: Executed first in C implementation for early rejection
     * ==================================================================== */
    for (i = 0; i < strong_iters; ++i) {
        /* Algorithm CHVL Line 12: P <-$ [0, n-1] */
        if (!ct_random_in_range(P, w1, 0, 0, top_w, ctx)) goto err;

        /* Algorithm CHVL Line 13: pass <- CSL(P, D, e, n) (Strong Lucas Evaluation) */
        ct_mont_mul(R1_A, P, &(mont->RR), mont, top_w, ct_tmp); 
        ct_bn_copy(R1_B, mont_one, top_w);
        ct_bn_copy(R0_A, mont_one, top_w);
        ct_mod_sub(R0_B, mont_one, mont_one, w1, top_w, ct_tmp); 

        for (j = bit_len - 1; j >= 0; --j) {
            int word_idx = j / BN_BITS2;
            int bit_idx = j % BN_BITS2;
            bit = (int)((e->d[word_idx] >> bit_idx) & 1);

            ct_swap_arrays(bit, R0_A, R1_A, top_w);
            ct_swap_arrays(bit, R0_B, R1_B, top_w);

            ct_mod_add(m1, R0_A, R0_B, w1, top_w, ct_tmp);
            ct_mod_add(m2, R1_A, R1_B, w1, top_w, ct_tmp);
            
            ct_mont_mul(m3, m1, m2, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, R0_A, R1_A, mont, top_w, ct_tmp); 
            ct_mont_mul(m2, R0_B, R1_B, mont, top_w, ct_tmp); 
            ct_mont_mul(tB1D, m2, D_mont, mont, top_w, ct_tmp); 
            
            ct_mod_add(R1_A, m1, tB1D, w1, top_w, ct_tmp);
            ct_mod_sub(R1_B, m3, m1, w1, top_w, ct_tmp);
            ct_mod_sub(R1_B, R1_B, m2, w1, top_w, ct_tmp);

            ct_mont_mul(m3, R0_A, R0_B, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, R0_A, R0_A, mont, top_w, ct_tmp); 
            ct_mont_mul(m2, R0_B, R0_B, mont, top_w, ct_tmp); 
            ct_mont_mul(tB1D, m2, D_mont, mont, top_w, ct_tmp); 
            
            ct_mod_add(R0_A, m1, tB1D, w1, top_w, ct_tmp);
            ct_mod_add(R0_B, m3, m3, w1, top_w, ct_tmp);

            ct_swap_arrays(bit, R0_A, R1_A, top_w);
            ct_swap_arrays(bit, R0_B, R1_B, top_w);
        }

        ct_mont_mul(temp_A, R0_A, plain_one, mont, top_w, ct_tmp); 
        ct_mont_mul(temp_B, R0_B, plain_one, mont, top_w, ct_tmp); 

        int pass_this_round = ct_bn_is_zero(temp_A, top_w) | ct_bn_is_zero(temp_B, top_w);
        
        /* Algorithm CHVL Line 14: is_composite <- is_composite | ~pass */
        is_composite |= (1 - pass_this_round);
    }

    /* ====================================================================
     * Phase 2: Amortized Setup & Constant-Time Trace Ladder (IVset)
     * ==================================================================== */
    int vset_iters = iterations - strong_iters;
    if (vset_iters > 0) {
        BIGNUM **batch_P = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_m3 = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_inv = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));

        if (batch_P == NULL || batch_m3 == NULL || batch_inv == NULL) {
            if (batch_P) OPENSSL_free(batch_P);
            if (batch_m3) OPENSSL_free(batch_m3);
            if (batch_inv) OPENSSL_free(batch_inv);
            goto err;
        }

        for (int k = 0; k < vset_iters; k++) {
            batch_P[k] = BN_CTX_get(ctx);
            batch_m3[k] = BN_CTX_get(ctx);
            batch_inv[k] = BN_CTX_get(ctx);
            if (batch_P[k] == NULL || batch_m3[k] == NULL || batch_inv[k] == NULL) goto err;
            bn_wexpand(batch_P[k], top_w); ct_pad_top(batch_P[k], top_w);
            bn_wexpand(batch_m3[k], top_w); ct_pad_top(batch_m3[k], top_w);
            bn_wexpand(batch_inv[k], top_w); ct_pad_top(batch_inv[k], top_w);
        }

        /* Algorithm CHVL Line 6: P <- Sample_Array(IVset, [0, n-1]) */
        for (int k = 0; k < vset_iters; k++) {
            if (!ct_random_in_range(batch_P[k], w1, 0, 0, top_w, ctx))
                goto err;

            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 

            /* Compute P^2 - D for batch inversion */
            ct_mod_sub(batch_m3[k], m1, D, w1, top_w, ct_tmp);          
        }

        /* Algorithm CHVL Line 7: (Inv, Coprime_Flags) <- CT_Batch_Invert({P^2 - D}) */
        if (!ct_batch_invert_mont(batch_inv, batch_m3, vset_iters, w1, top_w, ctx, mont, plain_one, ct_tmp, &is_composite)) {
            goto err;
        }

        /* Algorithm CHVL Line 8: For iter = 1 to IVset */
        for (int k = 0; k < vset_iters; k++) {
            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 
            ct_mod_add(m2, m1, D, w1, top_w, ct_tmp);

            ct_bn_copy(temp_A, batch_inv[k], top_w);
            
            /* Algorithm CHVL Line 10: V_init <- 2(P^2 + D) * Inv[iter] mod n */
            ct_mont_mul(m2, m2, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_A, temp_A, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, m2, temp_A, mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, temp_B, plain_one, mont, top_w, ct_tmp);
            
            ct_mod_add(temp_B, temp_B, temp_B, w1, top_w, ct_tmp); 

            /* Algorithm CHVL Line 11: pass <- CV(V_init, e, n) (Trace Evaluation) */
            ct_mont_mul(c_mont, temp_B, &(mont->RR), mont, top_w, ct_tmp); 
            ct_bn_copy(R1_A, c_mont, top_w);
            ct_bn_copy(R0_A, mont_two, top_w);                     

            for (j = bit_len - 1; j >= 0; --j) {
                int word_idx = j / BN_BITS2;
                int bit_idx = j % BN_BITS2;
                bit = (int)((e->d[word_idx] >> bit_idx) & 1);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);

                ct_mont_mul(m1, R0_A, R1_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R1_A, m1, c_mont, w1, top_w, ct_tmp);

                ct_mont_mul(m2, R0_A, R0_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R0_A, m2, mont_two, w1, top_w, ct_tmp);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);
            }

            ct_mont_mul(temp_A, R0_A, plain_one, mont, top_w, ct_tmp); 
            ct_bn_copy(temp_B, plain_two, top_w);
            
            ct_mod_sub(m1, temp_A, temp_B, w1, top_w, ct_tmp);      
            ct_mod_sub(m2, temp_A, w_minus_two, w1, top_w, ct_tmp); 
            
            int pass_this_round = ct_bn_is_zero(m1, top_w) | ct_bn_is_zero(m2, top_w);
            
            /* Algorithm CHVL Line 12: is_composite <- is_composite | ~pass */
            is_composite |= (1 - pass_this_round);
        }

        OPENSSL_free(batch_P); 
        OPENSSL_free(batch_m3); 
        OPENSSL_free(batch_inv);
    }

    /* Algorithm CHVL Line 15: Return ~is_composite */
    *status = is_composite ? BN_PRIMETEST_COMPOSITE : BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

int ossl_bn_CHVL_is_prime_random(const BIGNUM *w, int iterations, BN_CTX *ctx,
                           BN_GENCB *cb, int *status)
{
    int i, j, bit, bit_len, ret = 0;
    BIGNUM *w1, *e, *D, *D_mont, *P, *mont_one, *mont_two, *w_minus_two, *c_mont;
    BIGNUM *R0_A, *R0_B, *R1_A, *R1_B;
    BIGNUM *m1, *m2, *m3, *tB1D, *temp_A, *temp_B, *tmp_prime, *ct_tmp, *plain_one, *plain_two;
    BN_MONT_CTX *mont = NULL;
    
    if (!BN_is_odd(w)) return 0;

    BN_CTX_start(ctx);
    
    w1 = BN_CTX_get(ctx); e = BN_CTX_get(ctx); 
    D = BN_CTX_get(ctx); D_mont = BN_CTX_get(ctx);
    P = BN_CTX_get(ctx); 
    mont_one = BN_CTX_get(ctx); mont_two = BN_CTX_get(ctx);
    w_minus_two = BN_CTX_get(ctx); c_mont = BN_CTX_get(ctx);
    R0_A = BN_CTX_get(ctx); R0_B = BN_CTX_get(ctx);
    R1_A = BN_CTX_get(ctx); R1_B = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx); m2 = BN_CTX_get(ctx); m3 = BN_CTX_get(ctx); 
    tB1D = BN_CTX_get(ctx); temp_A = BN_CTX_get(ctx); temp_B = BN_CTX_get(ctx);
    tmp_prime = BN_CTX_get(ctx); ct_tmp = BN_CTX_get(ctx); 
    plain_one = BN_CTX_get(ctx); plain_two = BN_CTX_get(ctx);

    if (plain_two == NULL) goto err;

    if (!BN_copy(w1, w)) goto err;
    BN_set_flags(w1, BN_FLG_CONSTTIME);

    int top_w = w1->top;

    BIGNUM *all_vars[] = {w1, e, D, D_mont, P, mont_one, mont_two, w_minus_two, c_mont,
                          R0_A, R0_B, R1_A, R1_B, m1, m2, m3, tB1D, temp_A, temp_B, tmp_prime, ct_tmp, plain_one, plain_two};
    for (int k = 0; k < 23; k++) {
        if (!bn_wexpand(all_vars[k], top_w)) goto err;
        ct_pad_top(all_vars[k], top_w);
    }

    /* ====================================================================
     * Phase 1: Parameter Setup & CFindD Algorithm
     * ==================================================================== */
    
    /* Algorithm CFindD Line 1: D <- 0, found <- false */
    int found_mask = 0;
    BN_zero(D); ct_pad_top(D, top_w);

    /* Algorithm CFindD Line 2-3: J_target <- CTSelect(is_3_mod_4, 1, -1) */
    int is_3_mod_4 = BN_is_bit_set(w, 1); 
    int target_j_val = is_3_mod_4 ? 1 : -1;
    
    /* Algorithm CFindD Line 4: Random sampling for exactly 40 iterations */
    for (int k = 0; k < 40; k++) {
        /* Generate candidate D uniformly in [1, n-1] */
        if (!ct_random_in_range(tmp_prime, w1, 1, 1, top_w, ctx)) goto err;

        /* Algorithm CFindD Line 5: val <- ConstantTimeJacobi(candidate, n) */
        int j_val = ossl_bn_jacobi_by(tmp_prime, w, ctx); 
        
        /* Algorithm CFindD Lines 6-8: Conditionally update D */
        int is_match = (j_val == target_j_val);
        int update = is_match & (!found_mask);
        
        ct_swap_arrays(update, D, tmp_prime, top_w);
        found_mask |= update;
    }

    /* Algorithm CHVL Line 2: is_composite <- ~success */
    int is_composite = (1 - found_mask);

    /* Algorithm CHVL Lines 4-5: e <- (n + modifier) / 2 */
    ct_bn_copy_padded(e, w1, top_w);
    ct_bn_rshift1(e, top_w);
    ct_bn_add_word(e, 1 - (int)is_3_mod_4, top_w);
    
    bit_len = BN_num_bits(w1) - 1; 

    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w1, ctx)) goto err;
    
    BN_one(plain_one); ct_pad_top(plain_one, top_w);
    BN_set_word(plain_two, 2); ct_pad_top(plain_two, top_w);

    ct_mont_mul(D_mont, D, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_one, plain_one, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_two, plain_two, &(mont->RR), mont, top_w, ct_tmp);
    
    ct_mod_sub(w_minus_two, w1, plain_two, w1, top_w, ct_tmp);
    
    /* Dynamic split of iterations: Max 6 for Strong Lucas (ILPBP), rest for V-set (IVset) */
    const int NUM_STRONG_TESTS = 6;
    int strong_iters = (iterations < NUM_STRONG_TESTS) ? iterations : NUM_STRONG_TESTS;

    /* ====================================================================
     * Phase 3: Constant-Time Extension Ring Ladder (ILPBP Iterations)
     * Note: Executed first in C implementation for early rejection
     * ==================================================================== */
    for (i = 0; i < strong_iters; ++i) {
        /* Algorithm CHVL Line 12: P <-$ [0, n-1] */
        if (!ct_random_in_range(P, w1, 0, 0, top_w, ctx)) goto err;

        /* Algorithm CHVL Line 13: pass <- CSL(P, D, e, n) (Strong Lucas Evaluation) */
        ct_mont_mul(R1_A, P, &(mont->RR), mont, top_w, ct_tmp); 
        ct_bn_copy(R1_B, mont_one, top_w);
        ct_bn_copy(R0_A, mont_one, top_w);
        ct_mod_sub(R0_B, mont_one, mont_one, w1, top_w, ct_tmp); 

        for (j = bit_len - 1; j >= 0; --j) {
            int word_idx = j / BN_BITS2;
            int bit_idx = j % BN_BITS2;
            bit = (int)((e->d[word_idx] >> bit_idx) & 1);

            ct_swap_arrays(bit, R0_A, R1_A, top_w);
            ct_swap_arrays(bit, R0_B, R1_B, top_w);

            ct_mod_add(m1, R0_A, R0_B, w1, top_w, ct_tmp);
            ct_mod_add(m2, R1_A, R1_B, w1, top_w, ct_tmp);
            
            ct_mont_mul(m3, m1, m2, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, R0_A, R1_A, mont, top_w, ct_tmp); 
            ct_mont_mul(m2, R0_B, R1_B, mont, top_w, ct_tmp); 
            ct_mont_mul(tB1D, m2, D_mont, mont, top_w, ct_tmp); 
            
            ct_mod_add(R1_A, m1, tB1D, w1, top_w, ct_tmp);
            ct_mod_sub(R1_B, m3, m1, w1, top_w, ct_tmp);
            ct_mod_sub(R1_B, R1_B, m2, w1, top_w, ct_tmp);

            ct_mont_mul(m3, R0_A, R0_B, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, R0_A, R0_A, mont, top_w, ct_tmp); 
            ct_mont_mul(m2, R0_B, R0_B, mont, top_w, ct_tmp); 
            ct_mont_mul(tB1D, m2, D_mont, mont, top_w, ct_tmp); 
            
            ct_mod_add(R0_A, m1, tB1D, w1, top_w, ct_tmp);
            ct_mod_add(R0_B, m3, m3, w1, top_w, ct_tmp);

            ct_swap_arrays(bit, R0_A, R1_A, top_w);
            ct_swap_arrays(bit, R0_B, R1_B, top_w);
        }

        ct_mont_mul(temp_A, R0_A, plain_one, mont, top_w, ct_tmp); 
        ct_mont_mul(temp_B, R0_B, plain_one, mont, top_w, ct_tmp); 

        int pass_this_round = ct_bn_is_zero(temp_A, top_w) | ct_bn_is_zero(temp_B, top_w);
        
        /* Algorithm CHVL Line 14: is_composite <- is_composite | ~pass */
        is_composite |= (1 - pass_this_round);
    }

    /* ====================================================================
     * Phase 2: Amortized Setup & Constant-Time Trace Ladder (IVset)
     * ==================================================================== */
    int vset_iters = iterations - strong_iters;
    if (vset_iters > 0) {
        BIGNUM **batch_P = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_m3 = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_inv = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));

        if (batch_P == NULL || batch_m3 == NULL || batch_inv == NULL) {
            if (batch_P) OPENSSL_free(batch_P);
            if (batch_m3) OPENSSL_free(batch_m3);
            if (batch_inv) OPENSSL_free(batch_inv);
            goto err;
        }

        for (int k = 0; k < vset_iters; k++) {
            batch_P[k] = BN_CTX_get(ctx);
            batch_m3[k] = BN_CTX_get(ctx);
            batch_inv[k] = BN_CTX_get(ctx);
            if (batch_P[k] == NULL || batch_m3[k] == NULL || batch_inv[k] == NULL) goto err;
            bn_wexpand(batch_P[k], top_w); ct_pad_top(batch_P[k], top_w);
            bn_wexpand(batch_m3[k], top_w); ct_pad_top(batch_m3[k], top_w);
            bn_wexpand(batch_inv[k], top_w); ct_pad_top(batch_inv[k], top_w);
        }

        /* Algorithm CHVL Line 6: P <- Sample_Array(IVset, [0, n-1]) */
        for (int k = 0; k < vset_iters; k++) {
            if (!ct_random_in_range(batch_P[k], w1, 0, 0, top_w, ctx))
                goto err;

            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 

            /* Compute P^2 - D for batch inversion */
            ct_mod_sub(batch_m3[k], m1, D, w1, top_w, ct_tmp);          
        }

        /* Algorithm CHVL Line 7: (Inv, Coprime_Flags) <- CT_Batch_Invert({P^2 - D}) */
        if (!ct_batch_invert_mont(batch_inv, batch_m3, vset_iters, w1, top_w, ctx, mont, plain_one, ct_tmp, &is_composite)) {
            goto err;
        }

        /* Algorithm CHVL Line 8: For iter = 1 to IVset */
        for (int k = 0; k < vset_iters; k++) {
            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 
            ct_mod_add(m2, m1, D, w1, top_w, ct_tmp);

            ct_bn_copy(temp_A, batch_inv[k], top_w);
            
            /* Algorithm CHVL Line 10: V_init <- 2(P^2 + D) * Inv[iter] mod n */
            ct_mont_mul(m2, m2, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_A, temp_A, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, m2, temp_A, mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, temp_B, plain_one, mont, top_w, ct_tmp);
            
            ct_mod_add(temp_B, temp_B, temp_B, w1, top_w, ct_tmp); 

            /* Algorithm CHVL Line 11: pass <- CV(V_init, e, n) (Trace Evaluation) */
            ct_mont_mul(c_mont, temp_B, &(mont->RR), mont, top_w, ct_tmp); 
            ct_bn_copy(R1_A, c_mont, top_w);
            ct_bn_copy(R0_A, mont_two, top_w);                     

            for (j = bit_len - 1; j >= 0; --j) {
                int word_idx = j / BN_BITS2;
                int bit_idx = j % BN_BITS2;
                bit = (int)((e->d[word_idx] >> bit_idx) & 1);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);

                ct_mont_mul(m1, R0_A, R1_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R1_A, m1, c_mont, w1, top_w, ct_tmp);

                ct_mont_mul(m2, R0_A, R0_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R0_A, m2, mont_two, w1, top_w, ct_tmp);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);
            }

            ct_mont_mul(temp_A, R0_A, plain_one, mont, top_w, ct_tmp); 
            ct_bn_copy(temp_B, plain_two, top_w);
            
            ct_mod_sub(m1, temp_A, temp_B, w1, top_w, ct_tmp);      
            ct_mod_sub(m2, temp_A, w_minus_two, w1, top_w, ct_tmp); 
            
            int pass_this_round = ct_bn_is_zero(m1, top_w) | ct_bn_is_zero(m2, top_w);
            
            /* Algorithm CHVL Line 12: is_composite <- is_composite | ~pass */
            is_composite |= (1 - pass_this_round);
        }

        OPENSSL_free(batch_P); 
        OPENSSL_free(batch_m3); 
        OPENSSL_free(batch_inv);
    }

    /* Algorithm CHVL Line 15: Return ~is_composite */
    *status = is_composite ? BN_PRIMETEST_COMPOSITE : BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

/*
 * Solovay-Strassen Probabilistic Primality Test
 * Computes:
 * 1. Jacobi symbol j = (a/w)
 * 2. Euler criterion x = a^{(w-1)/2} mod w
 * If x != j mod w, then w is composite.
 */
int ossl_bn_solovay_strassen_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
                                      BN_GENCB *cb, int *status)
{
    int i, ret = 0, j_val;
    BIGNUM *w1, *w_minus_2, *a, *x, *e;
    BIGNUM *expected, *bn_w1_copy, *diff, *ct_tmp, *plain_one;
    BN_MONT_CTX *mont = NULL;

    if (!BN_is_odd(w)) return 0;
    if (BN_cmp(w, BN_value_one()) <= 0) return 0;
    if (BN_is_word(w, 3)) { 
        *status = BN_PRIMETEST_PROBABLY_PRIME; 
        return 1; 
    }

    BN_CTX_start(ctx);
    
    w1 = BN_CTX_get(ctx); w_minus_2 = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx); x = BN_CTX_get(ctx); e = BN_CTX_get(ctx);
    expected = BN_CTX_get(ctx); bn_w1_copy = BN_CTX_get(ctx);
    diff = BN_CTX_get(ctx); ct_tmp = BN_CTX_get(ctx);
    plain_one = BN_CTX_get(ctx); 

    if (plain_one == NULL) goto err;

    if (!BN_copy(w1, w) || !BN_sub_word(w1, 1)) goto err;
    BN_set_flags(w1, BN_FLG_CONSTTIME);
    int top_w = w1->top;

    BIGNUM *all_vars[] = {w1, w_minus_2, a, x, e, expected, bn_w1_copy, diff, ct_tmp, plain_one};
    for (int k = 0; k < 10; k++) {
        if (!bn_wexpand(all_vars[k], top_w)) goto err;
        ct_pad_top(all_vars[k], top_w); 
    }

    if (!BN_copy(w_minus_2, w) || !BN_sub_word(w_minus_2, 2)) goto err;

    /* Algorithm Line 1: e <- (n-1)/2 */
    if (!BN_rshift1(e, w1)) goto err;
    BN_set_flags(e, BN_FLG_CONSTTIME);
    ct_pad_top(e, top_w); 

    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w, ctx)) goto err;

    BN_one(plain_one); 
    ct_pad_top(plain_one, top_w);

    /* Algorithm Line 2: is_composite <- false */
    int is_composite = 0;

    /* Algorithm Line 3: For i = 1 to k */
    for (i = 0; i < iterations; ++i) {
        /* Algorithm Line 4: a <-$ [1, n-1] */
        if (!ct_random_in_range(a, w, 1, 1, top_w, ctx)) goto err;

        /* Algorithm Line 6: j_val <- (a/n) (Constant-time Jacobi) */
        j_val = ossl_bn_jacobi_by(a, w, ctx);
        
        /* Algorithm Line 7: x <- a^e mod n (Evaluated via CT Montgomery Ladder) */
        if (!ct_mod_exp_mont_ladder(x, a, e, mont, top_w, ctx, plain_one, ct_tmp)) goto err;

        /* =========================================================
         * Step 3: Constant-Time Euler Criterion Check
         * ========================================================= */
        int is_j_zero = (j_val == 0);
        int is_j_minus_1 = (j_val == -1);

        ct_bn_copy(expected, plain_one, top_w); 
        
        ct_bn_copy_padded(bn_w1_copy, w1, top_w);

        /* Algorithm Line 9: expected <- CTSelect(j_val == -1, n-1, 1) */
        ct_swap_arrays(is_j_minus_1, expected, bn_w1_copy, top_w);
        ct_mod_sub(diff, x, expected, w, top_w, ct_tmp);

        /* Algorithm Line 10: match <- (x == expected mod n) & (j_val != 0) */
        int pass_this_round = ct_bn_is_zero(diff, top_w) & (1 - is_j_zero);
        
        /* Algorithm Line 11: is_composite <- is_composite | ~match */
        is_composite |= (1 - pass_this_round);
    }

    /* Algorithm Line 13: Return ~is_composite */
    *status = is_composite ? BN_PRIMETEST_COMPOSITE : BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

int ossl_bn_CHVSS_is_prime_random(const BIGNUM *w, int iterations, BN_CTX *ctx,
                                    BN_GENCB *cb, int *status)
{
    int i, j, bit, bit_len, ret = 0;
    
    BIGNUM *w_ct, *w_minus_1, *w_minus_2;
    BIGNUM *e_vset, *e_ss, *D, *D_mont, *P, *mont_one, *mont_two, *c_mont;
    BIGNUM *R0_A, *R1_A, *x_ss, *expected_ss, *tmp_base, *bn_w1_copy;
    BIGNUM *m1, *m2, *m3, *temp_A, *temp_B, *ct_tmp, *plain_one, *plain_two;
    BN_MONT_CTX *mont = NULL;
    
    /* is_composite <- false */
    int is_composite = 0;

    if (!BN_is_odd(w)) return 0;
    if (BN_cmp(w, BN_value_one()) <= 0) return 0;
    if (BN_is_word(w, 3)) { 
        *status = BN_PRIMETEST_PROBABLY_PRIME; 
        return 1; 
    }

    BN_CTX_start(ctx);
    
    w_ct = BN_CTX_get(ctx); w_minus_1 = BN_CTX_get(ctx); w_minus_2 = BN_CTX_get(ctx);
    e_vset = BN_CTX_get(ctx); e_ss = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx); D_mont = BN_CTX_get(ctx); P = BN_CTX_get(ctx); 
    mont_one = BN_CTX_get(ctx); mont_two = BN_CTX_get(ctx); c_mont = BN_CTX_get(ctx);
    R0_A = BN_CTX_get(ctx); R1_A = BN_CTX_get(ctx); 
    x_ss = BN_CTX_get(ctx); expected_ss = BN_CTX_get(ctx); tmp_base = BN_CTX_get(ctx);
    bn_w1_copy = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx); m2 = BN_CTX_get(ctx); m3 = BN_CTX_get(ctx); 
    temp_A = BN_CTX_get(ctx); temp_B = BN_CTX_get(ctx); ct_tmp = BN_CTX_get(ctx); 
    plain_one = BN_CTX_get(ctx); plain_two = BN_CTX_get(ctx);

    if (plain_two == NULL) goto err;

    if (!BN_copy(w_ct, w)) goto err;
    BN_set_flags(w_ct, BN_FLG_CONSTTIME);
    int top_w = w_ct->top;

    if (!BN_copy(w_minus_1, w) || !BN_sub_word(w_minus_1, 1)) goto err;
    BN_set_flags(w_minus_1, BN_FLG_CONSTTIME);

    if (!BN_copy(w_minus_2, w) || !BN_sub_word(w_minus_2, 2)) goto err;
    BN_set_flags(w_minus_2, BN_FLG_CONSTTIME);

    BIGNUM *vars[] = {w_ct, w_minus_1, w_minus_2, e_vset, e_ss, D, D_mont, P, mont_one, mont_two, c_mont,
                      R0_A, R1_A, x_ss, expected_ss, tmp_base, bn_w1_copy,
                      m1, m2, m3, temp_A, temp_B, ct_tmp, plain_one, plain_two};
    for (i = 0; i < 25; i++) {
        if (!bn_wexpand(vars[i], top_w)) goto err;
        ct_pad_top(vars[i], top_w);
    }

    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w_ct, ctx)) goto err;

    BN_one(plain_one); ct_pad_top(plain_one, top_w);
    BN_set_word(plain_two, 2); ct_pad_top(plain_two, top_w);
    BN_set_word(temp_A, 2); ct_pad_top(temp_A, top_w);

    /* D <- 0, found_D <- false */
    int found_D_mask = 0;
    
    /* is_3_mod_4 <- (n & 3) == 3 */
    int is_3_mod_4 = BN_is_bit_set(w_ct, 1);
    
    BN_zero(D); ct_pad_top(D, top_w);

    ct_bn_copy_padded(e_ss, w_minus_1, top_w); 
    ct_bn_rshift1(e_ss, top_w);

    /* J_target <- CTSelect(is_3_mod_4, 1, -1) */
    int target_j_val = is_3_mod_4 ? 1 : -1;
    
    /* iterations I_SS */
    int constSS = 7;
    
    /* ====================================================================
     * Phase 1A: Amortized SS Test & CT D Search
     * ==================================================================== */
    for (i = 0; i < constSS; i++) {
        /* a <-$ [1, n-1] */
        if (!ct_random_in_range(tmp_base, w_ct, 1, 1, top_w, ctx)) goto err;

        /* J <- (a/n) (Constant-time Jacobi) */
        int j_val = ossl_bn_jacobi_by(tmp_base, w_ct, ctx); 
        
        /* x <- a^{(n-1)/2} mod n (Evaluated via CT Montgomery Ladder) */
        if (!ct_mod_exp_mont_ladder(x_ss, tmp_base, e_ss, mont, top_w, ctx, plain_one, ct_tmp)) goto err; 
        
        /* Conditionally update D without branching */
        /* is_match <- (J == J_target) */
        int is_match = (j_val == target_j_val);
        /* update_D <- is_match & ~found_D */
        int update_D = is_match & (!found_D_mask);
        /* D <- CTSelect(update_D, a, D) */
        ct_swap_arrays(update_D, D, tmp_base, top_w);
        /* found_D <- found_D | update_D */
        found_D_mask |= update_D; 

        /* Verify SS condition: fail_SS <- (J == 0) | (x != J mod n) */
        int is_j_zero = (j_val == 0);
        int is_j_minus_1 = (j_val == -1); 

        BN_one(expected_ss); ct_pad_top(expected_ss, top_w);
        ct_bn_copy_padded(bn_w1_copy, w_minus_1, top_w);

        ct_swap_arrays(is_j_minus_1, expected_ss, bn_w1_copy, top_w);
        ct_mod_sub(m1, x_ss, expected_ss, w_ct, top_w, ct_tmp); 

        /* is_composite <- is_composite | fail_SS */
        int pass_this_round = ct_bn_is_zero(m1, top_w) & (1 - is_j_zero);
        is_composite |= (1 - pass_this_round);
    }

    /* ====================================================================
     * Phase 1B: Randomized Fallback Search (Always Executed)
     * ==================================================================== */
    int totalSmallPrimeTry = 40 - constSS;
    
    for (i = 0; i < totalSmallPrimeTry; i++) {
        /* 隨機選取 D_candidate <-$ [1, n-1] 取代原本固定陣列 */
        if (!ct_random_in_range(tmp_base, w_ct, 1, 1, top_w, ctx)) goto err;

        /* J <- (D_candidate/n) */
        int j_val = ossl_bn_jacobi_by(tmp_base, w_ct, ctx); 
        
        /* Conditionally update D without branching */
        int is_match = (j_val == target_j_val);
        int update_D = is_match & (!found_D_mask);
        ct_swap_arrays(update_D, D, tmp_base, top_w);
        found_D_mask |= update_D; 
    }

    /* is_composite <- is_composite | ~found_D (Structurally reject squares) */
    is_composite |= (1 - found_D_mask);

    /* ====================================================================
     * Phase 2: Amortized Setup & CT Ladder for vTraceLucas
     * ==================================================================== */
    ct_bn_copy_padded(e_vset, w_ct, top_w);
    
    /* modifier <- CTSelect(is_3_mod_4, -1, 1) */
    BN_ULONG add_val = is_3_mod_4 ? 0 : 1;
    BN_ULONG sub_val = is_3_mod_4 ? 1 : 0;
    
    BN_ULONG c = add_val;
    for (int k = 0; k < top_w; k++) {
        BN_ULONG sum = e_vset->d[k] + c;
        c = (sum < e_vset->d[k]) ? 1 : 0;
        e_vset->d[k] = sum;
    }
    c = sub_val;
    for (int k = 0; k < top_w; k++) {
        BN_ULONG diff = e_vset->d[k] - c;
        c = (e_vset->d[k] < c) ? 1 : 0;
        e_vset->d[k] = diff;
    }
    
    /* e <- (n + modifier) / 2 */
    ct_bn_rshift1(e_vset, top_w);
    bit_len = BN_num_bits(w_ct) - 1; 

    ct_mont_mul(D_mont, D, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_one, plain_one, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_two, temp_A, &(mont->RR), mont, top_w, ct_tmp);

    /* iterations I_Vset */
    int vset_iters = iterations - constSS;
    if (vset_iters < 0) vset_iters = 0;

    if (vset_iters > 0) {
        BIGNUM **batch_P = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_m3 = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_inv = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));

        if (batch_P == NULL || batch_m3 == NULL || batch_inv == NULL) {
            if (batch_P) OPENSSL_free(batch_P);
            if (batch_m3) OPENSSL_free(batch_m3);
            if (batch_inv) OPENSSL_free(batch_inv);
            goto err;
        }

        for (int k = 0; k < vset_iters; k++) {
            batch_P[k] = BN_CTX_get(ctx);
            batch_m3[k] = BN_CTX_get(ctx);
            batch_inv[k] = BN_CTX_get(ctx);
            if (batch_P[k] == NULL || batch_m3[k] == NULL || batch_inv[k] == NULL) goto err;
            bn_wexpand(batch_P[k], top_w); ct_pad_top(batch_P[k], top_w);
            bn_wexpand(batch_m3[k], top_w); ct_pad_top(batch_m3[k], top_w);
            bn_wexpand(batch_inv[k], top_w); ct_pad_top(batch_inv[k], top_w);
        }

        /* --- Crucial Optimization: Batch invert for all Trace iterations --- */
        
        /* Step A: P <- Sample_Array(I_Vset, [0, n-1]) */
        for (int k = 0; k < vset_iters; k++) {
            if (!ct_random_in_range(batch_P[k], w_ct, 0, 0, top_w, ctx)) goto err;

            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 

            /* Prepare array: {P^2 - D | P \in P} */
            ct_mod_sub(batch_m3[k], m1, D, w_ct, top_w, ct_tmp);          
        }

        /* Step B: (Inv, Coprime_Flags) <- CT_Batch_Invert(...) */
        if (!ct_batch_invert_mont(batch_inv, batch_m3, vset_iters, w_ct, top_w, ctx, mont, plain_one, ct_tmp, &is_composite)) {
            goto err;
        }

        /* Step C: Evaluate V_init and CV sequence for all I_Vset iterations */
        for (int k = 0; k < vset_iters; k++) {
            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 
            ct_mod_add(m2, m1, D, w_ct, top_w, ct_tmp);

            ct_bn_copy(temp_A, batch_inv[k], top_w);
            
            /* V_init <- 2(P^2 + D) * Inv[iter] mod n */
            ct_mont_mul(m2, m2, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_A, temp_A, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, m2, temp_A, mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, temp_B, plain_one, mont, top_w, ct_tmp);
            
            ct_mod_add(temp_B, temp_B, temp_B, w_ct, top_w, ct_tmp); 

            ct_mont_mul(c_mont, temp_B, &(mont->RR), mont, top_w, ct_tmp); 
            ct_bn_copy(R1_A, c_mont, top_w);                       
            ct_bn_copy(R0_A, mont_two, top_w);                     

            /* Evaluate CV(V_init, e, n) via CT Ladder */
            for (j = bit_len - 1; j >= 0; --j) {
                int word_idx = j / BN_BITS2;
                int bit_idx = j % BN_BITS2;
                bit = (int)((e_vset->d[word_idx] >> bit_idx) & 1);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);

                ct_mont_mul(m1, R0_A, R1_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R1_A, m1, c_mont, w_ct, top_w, ct_tmp);

                ct_mont_mul(m2, R0_A, R0_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R0_A, m2, mont_two, w_ct, top_w, ct_tmp);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);
            }

            ct_mont_mul(temp_A, R0_A, plain_one, mont, top_w, ct_tmp); 
            
            ct_bn_copy(temp_B, plain_two, top_w);
            
            /* pass <- (V_e == 2) || (V_e == n - 2) */
            ct_mod_sub(m1, temp_A, temp_B, w_ct, top_w, ct_tmp);      
            ct_mod_sub(m2, temp_A, w_minus_2, w_ct, top_w, ct_tmp); 
            
            int pass_this_round = ct_bn_is_zero(m1, top_w) | ct_bn_is_zero(m2, top_w);
            
            /* is_composite <- is_composite | ~pass */
            is_composite |= (1 - pass_this_round);
        }

        OPENSSL_free(batch_P); 
        OPENSSL_free(batch_m3); 
        OPENSSL_free(batch_inv);
    }

    /* Return ~is_composite */
    *status = is_composite ? BN_PRIMETEST_COMPOSITE : BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

int ossl_bn_CHVSS_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
                                    BN_GENCB *cb, int *status)
{
    int i, j, bit, bit_len, ret = 0;
    
    BIGNUM *w_ct, *w_minus_1, *w_minus_2;
    BIGNUM *e_vset, *e_ss, *D, *D_mont, *P, *mont_one, *mont_two, *c_mont;
    BIGNUM *R0_A, *R1_A, *x_ss, *expected_ss, *tmp_base, *bn_w1_copy;
    BIGNUM *m1, *m2, *m3, *temp_A, *temp_B, *ct_tmp, *plain_one, *plain_two;
    BN_MONT_CTX *mont = NULL;
    
    /* is_composite <- false */
    int is_composite = 0;

    if (!BN_is_odd(w)) return 0;
    if (BN_cmp(w, BN_value_one()) <= 0) return 0;
    if (BN_is_word(w, 3)) { 
        *status = BN_PRIMETEST_PROBABLY_PRIME; 
        return 1; 
    }

    BN_CTX_start(ctx);
    
    w_ct = BN_CTX_get(ctx); w_minus_1 = BN_CTX_get(ctx); w_minus_2 = BN_CTX_get(ctx);
    e_vset = BN_CTX_get(ctx); e_ss = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx); D_mont = BN_CTX_get(ctx); P = BN_CTX_get(ctx); 
    mont_one = BN_CTX_get(ctx); mont_two = BN_CTX_get(ctx); c_mont = BN_CTX_get(ctx);
    R0_A = BN_CTX_get(ctx); R1_A = BN_CTX_get(ctx); 
    x_ss = BN_CTX_get(ctx); expected_ss = BN_CTX_get(ctx); tmp_base = BN_CTX_get(ctx);
    bn_w1_copy = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx); m2 = BN_CTX_get(ctx); m3 = BN_CTX_get(ctx); 
    temp_A = BN_CTX_get(ctx); temp_B = BN_CTX_get(ctx); ct_tmp = BN_CTX_get(ctx); 
    plain_one = BN_CTX_get(ctx); plain_two = BN_CTX_get(ctx);

    if (plain_two == NULL) goto err;

    if (!BN_copy(w_ct, w)) goto err;
    BN_set_flags(w_ct, BN_FLG_CONSTTIME);
    int top_w = w_ct->top;

    if (!BN_copy(w_minus_1, w) || !BN_sub_word(w_minus_1, 1)) goto err;
    BN_set_flags(w_minus_1, BN_FLG_CONSTTIME);

    if (!BN_copy(w_minus_2, w) || !BN_sub_word(w_minus_2, 2)) goto err;
    BN_set_flags(w_minus_2, BN_FLG_CONSTTIME);

    BIGNUM *vars[] = {w_ct, w_minus_1, w_minus_2, e_vset, e_ss, D, D_mont, P, mont_one, mont_two, c_mont,
                      R0_A, R1_A, x_ss, expected_ss, tmp_base, bn_w1_copy,
                      m1, m2, m3, temp_A, temp_B, ct_tmp, plain_one, plain_two};
    for (i = 0; i < 25; i++) {
        if (!bn_wexpand(vars[i], top_w)) goto err;
        ct_pad_top(vars[i], top_w);
    }

    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w_ct, ctx)) goto err;

    BN_one(plain_one); ct_pad_top(plain_one, top_w);
    BN_set_word(plain_two, 2); ct_pad_top(plain_two, top_w);
    BN_set_word(temp_A, 2); ct_pad_top(temp_A, top_w);

    /* D <- 0, found_D <- false */
    int found_D_mask = 0;
    
    /* is_3_mod_4 <- (n & 3) == 3 */
    int is_3_mod_4 = BN_is_bit_set(w_ct, 1);
    
    BN_zero(D); ct_pad_top(D, top_w);

    ct_bn_copy_padded(e_ss, w_minus_1, top_w); 
    ct_bn_rshift1(e_ss, top_w);

    /* J_target <- CTSelect(is_3_mod_4, 1, -1) */
    int target_j_val = is_3_mod_4 ? 1 : -1;
    
    /* iterations I_SS */
    int constSS = 7;
    
    /* ====================================================================
     * Phase 1A: Amortized SS Test & CT D Search
     * ==================================================================== */
    for (i = 0; i < constSS; i++) {
        /* a <-$ [1, n-1] */
        if (!ct_random_in_range(tmp_base, w_ct, 1, 1, top_w, ctx)) goto err;

        /* J <- (a/n) (Constant-time Jacobi) */
        int j_val = ossl_bn_jacobi_by(tmp_base, w_ct, ctx); 
        
        /* x <- a^{(n-1)/2} mod n (Evaluated via CT Montgomery Ladder) */
        if (!ct_mod_exp_mont_ladder(x_ss, tmp_base, e_ss, mont, top_w, ctx, plain_one, ct_tmp)) goto err; 
        
        /* Conditionally update D without branching */
        /* is_match <- (J == J_target) */
        int is_match = (j_val == target_j_val);
        /* update_D <- is_match & ~found_D */
        int update_D = is_match & (!found_D_mask);
        /* D <- CTSelect(update_D, a, D) */
        ct_swap_arrays(update_D, D, tmp_base, top_w);
        /* found_D <- found_D | update_D */
        found_D_mask |= update_D; 

        /* Verify SS condition: fail_SS <- (J == 0) | (x != J mod n) */
        int is_j_zero = (j_val == 0);
        int is_j_minus_1 = (j_val == -1); 

        BN_one(expected_ss); ct_pad_top(expected_ss, top_w);
        ct_bn_copy_padded(bn_w1_copy, w_minus_1, top_w);

        ct_swap_arrays(is_j_minus_1, expected_ss, bn_w1_copy, top_w);
        ct_mod_sub(m1, x_ss, expected_ss, w_ct, top_w, ct_tmp); 

        /* is_composite <- is_composite | fail_SS */
        int pass_this_round = ct_bn_is_zero(m1, top_w) & (1 - is_j_zero);
        is_composite |= (1 - pass_this_round);
    }

    /* ====================================================================
     * Phase 1B: Deterministic Fallback Search (Always Executed)
     * ==================================================================== */
    /* L <- {3, 5, 7, ..., p_{I_fb}} (Array of I_fb small primes) */
    int totalSmallPrimeTry = 40 - constSS;
    static const int small_primes[40] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179
    };
    for (i = 0; i < totalSmallPrimeTry; i++) {
        BN_set_word(tmp_base, small_primes[i]);
        ct_pad_top(tmp_base, top_w);

        /* J <- (p/n) */
        int j_val = ossl_bn_jacobi_by(tmp_base, w_ct, ctx); 
        
        /* Conditionally update D without branching */
        int is_match = (j_val == target_j_val);
        int update_D = is_match & (!found_D_mask);
        ct_swap_arrays(update_D, D, tmp_base, top_w);
        found_D_mask |= update_D; 
    }

    /* is_composite <- is_composite | ~found_D (Structurally reject squares) */
    is_composite |= (1 - found_D_mask);

    /* ====================================================================
     * Phase 2: Amortized Setup & CT Ladder for vTraceLucas
     * ==================================================================== */
    ct_bn_copy_padded(e_vset, w_ct, top_w);
    
    /* modifier <- CTSelect(is_3_mod_4, -1, 1) */
    BN_ULONG add_val = is_3_mod_4 ? 0 : 1;
    BN_ULONG sub_val = is_3_mod_4 ? 1 : 0;
    
    BN_ULONG c = add_val;
    for (int k = 0; k < top_w; k++) {
        BN_ULONG sum = e_vset->d[k] + c;
        c = (sum < e_vset->d[k]) ? 1 : 0;
        e_vset->d[k] = sum;
    }
    c = sub_val;
    for (int k = 0; k < top_w; k++) {
        BN_ULONG diff = e_vset->d[k] - c;
        c = (e_vset->d[k] < c) ? 1 : 0;
        e_vset->d[k] = diff;
    }
    
    /* e <- (n + modifier) / 2 */
    ct_bn_rshift1(e_vset, top_w);
    bit_len = BN_num_bits(w_ct) - 1; 

    ct_mont_mul(D_mont, D, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_one, plain_one, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_two, temp_A, &(mont->RR), mont, top_w, ct_tmp);

    /* iterations I_Vset */
    int vset_iters = iterations - constSS;
    if (vset_iters < 0) vset_iters = 0;

    if (vset_iters > 0) {
        BIGNUM **batch_P = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_m3 = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));
        BIGNUM **batch_inv = OPENSSL_malloc(vset_iters * sizeof(BIGNUM *));

        if (batch_P == NULL || batch_m3 == NULL || batch_inv == NULL) {
            if (batch_P) OPENSSL_free(batch_P);
            if (batch_m3) OPENSSL_free(batch_m3);
            if (batch_inv) OPENSSL_free(batch_inv);
            goto err;
        }

        for (int k = 0; k < vset_iters; k++) {
            batch_P[k] = BN_CTX_get(ctx);
            batch_m3[k] = BN_CTX_get(ctx);
            batch_inv[k] = BN_CTX_get(ctx);
            if (batch_P[k] == NULL || batch_m3[k] == NULL || batch_inv[k] == NULL) goto err;
            bn_wexpand(batch_P[k], top_w); ct_pad_top(batch_P[k], top_w);
            bn_wexpand(batch_m3[k], top_w); ct_pad_top(batch_m3[k], top_w);
            bn_wexpand(batch_inv[k], top_w); ct_pad_top(batch_inv[k], top_w);
        }

        /* --- Crucial Optimization: Batch invert for all Trace iterations --- */
        
        /* Step A: P <- Sample_Array(I_Vset, [0, n-1]) */
        for (int k = 0; k < vset_iters; k++) {
            if (!ct_random_in_range(batch_P[k], w_ct, 0, 0, top_w, ctx)) goto err;

            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 

            /* Prepare array: {P^2 - D | P \in P} */
            ct_mod_sub(batch_m3[k], m1, D, w_ct, top_w, ct_tmp);          
        }

        /* Step B: (Inv, Coprime_Flags) <- CT_Batch_Invert(...) */
        if (!ct_batch_invert_mont(batch_inv, batch_m3, vset_iters, w_ct, top_w, ctx, mont, plain_one, ct_tmp, &is_composite)) {
            goto err;
        }

        /* Step C: Evaluate V_init and CV sequence for all I_Vset iterations */
        for (int k = 0; k < vset_iters; k++) {
            ct_mont_mul(m1, batch_P[k], &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(m1, m1, m1, mont, top_w, ct_tmp); 
            ct_mont_mul(m1, m1, plain_one, mont, top_w, ct_tmp); 
            ct_mod_add(m2, m1, D, w_ct, top_w, ct_tmp);

            ct_bn_copy(temp_A, batch_inv[k], top_w);
            
            /* V_init <- 2(P^2 + D) * Inv[iter] mod n */
            ct_mont_mul(m2, m2, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_A, temp_A, &(mont->RR), mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, m2, temp_A, mont, top_w, ct_tmp);
            ct_mont_mul(temp_B, temp_B, plain_one, mont, top_w, ct_tmp);
            
            ct_mod_add(temp_B, temp_B, temp_B, w_ct, top_w, ct_tmp); 

            ct_mont_mul(c_mont, temp_B, &(mont->RR), mont, top_w, ct_tmp); 
            ct_bn_copy(R1_A, c_mont, top_w);                       
            ct_bn_copy(R0_A, mont_two, top_w);                     

            /* Evaluate CV(V_init, e, n) via CT Ladder */
            for (j = bit_len - 1; j >= 0; --j) {
                int word_idx = j / BN_BITS2;
                int bit_idx = j % BN_BITS2;
                bit = (int)((e_vset->d[word_idx] >> bit_idx) & 1);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);

                ct_mont_mul(m1, R0_A, R1_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R1_A, m1, c_mont, w_ct, top_w, ct_tmp);

                ct_mont_mul(m2, R0_A, R0_A, mont, top_w, ct_tmp); 
                ct_mod_sub(R0_A, m2, mont_two, w_ct, top_w, ct_tmp);

                ct_swap_arrays(bit, R0_A, R1_A, top_w);
            }

            ct_mont_mul(temp_A, R0_A, plain_one, mont, top_w, ct_tmp); 
            
            ct_bn_copy(temp_B, plain_two, top_w);
            
            /* pass <- (V_e == 2) || (V_e == n - 2) */
            ct_mod_sub(m1, temp_A, temp_B, w_ct, top_w, ct_tmp);      
            ct_mod_sub(m2, temp_A, w_minus_2, w_ct, top_w, ct_tmp); 
            
            int pass_this_round = ct_bn_is_zero(m1, top_w) | ct_bn_is_zero(m2, top_w);
            
            /* is_composite <- is_composite | ~pass */
            is_composite |= (1 - pass_this_round);
        }

        OPENSSL_free(batch_P); 
        OPENSSL_free(batch_m3); 
        OPENSSL_free(batch_inv);
    }

    /* Return ~is_composite */
    *status = is_composite ? BN_PRIMETEST_COMPOSITE : BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

int ossl_bn_miller_rabin_is_prime_unified(const BIGNUM *w, int iterations, BN_CTX *ctx,
                                          BN_GENCB *cb, int *status)
{
    int i, j, ret = 0;
    BIGNUM *w1, *w3, *b, *R0, *R1, *t1;
    BIGNUM *mont_one, *mont_w1, *ct_tmp, *plain_one; 
    BN_MONT_CTX *mont = NULL;

    if (!BN_is_odd(w)) return 0;
    if (BN_cmp(w, BN_value_one()) <= 0) return 0;
    if (BN_is_word(w, 3)) { *status = BN_PRIMETEST_PROBABLY_PRIME; return 1; }

    BN_CTX_start(ctx);
    w1 = BN_CTX_get(ctx); w3 = BN_CTX_get(ctx); b = BN_CTX_get(ctx);
    R0 = BN_CTX_get(ctx); R1 = BN_CTX_get(ctx); t1 = BN_CTX_get(ctx);
    mont_one = BN_CTX_get(ctx); mont_w1 = BN_CTX_get(ctx);
    ct_tmp = BN_CTX_get(ctx); plain_one = BN_CTX_get(ctx);

    if (plain_one == NULL) goto err;

    if (!BN_copy(w1, w) || !BN_sub_word(w1, 1)) goto err;
    BN_set_flags(w1, BN_FLG_CONSTTIME);
    int top_w = w1->top;
    
    /* Algorithm Line 1: L <- bit length of n-1 */
    int bit_len = BN_num_bits(w1);

    if (!BN_copy(w3, w) || !BN_sub_word(w3, 3)) goto err;

    /* Array size reduced from 11 to 10 */
    BIGNUM *all_vars[] = {w1, w3, b, R0, R1, t1, mont_one, mont_w1, ct_tmp, plain_one};
    for (int k = 0; k < 10; k++) {
        if (!bn_wexpand(all_vars[k], top_w)) goto err;
        ct_pad_top(all_vars[k], top_w); 
    }

    BN_one(plain_one); ct_pad_top(plain_one, top_w); 
    
    /* Algorithm Line 2: s <- count trailing zeros of n-1 (Constant-Time Implementation) */
    int s = 0;
    int found_one = 0;
    for (int k = 0; k < bit_len; k++) {
        int word_idx = k / BN_BITS2;
        int bit_idx = k % BN_BITS2;
        int bit_val = (int)((w1->d[word_idx] >> bit_idx) & 1);
        found_one |= bit_val;
        s += (1 - found_one);
    }

    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, w, ctx)) goto err;
    ct_mont_mul(mont_one, plain_one, &(mont->RR), mont, top_w, ct_tmp);
    ct_mont_mul(mont_w1, w1, &(mont->RR), mont, top_w, ct_tmp);

    if (iterations == 0) iterations = bn_mr_min_checks(BN_num_bits(w));

    /* Algorithm Line 3: is_composite <- false */
    int is_composite = 0;

    /* Algorithm Line 4: For i = 1 to k */
    for (i = 0; i < iterations; ++i) {
        /* Algorithm Line 5: a <-$ [1, n-1] */
        if (!ct_random_in_range(b, w, 1, 1, top_w, ctx)) goto err;

        /* Algorithm Line 6: R_0 <- 1, R_1 <- a mod n (in Montgomery domain) */
        ct_bn_copy(R0, mont_one, top_w); 
        ct_mont_mul(R1, b, &(mont->RR), mont, top_w, ct_tmp); 

        /* Algorithm Line 7: pass_round <- false */
        int pass_this_round = 0;

        /* Algorithm Lines 8-9: Fixed-length Montgomery Ladder (For j = L-1 to 0) */
        for (j = bit_len - 1; j >= 0; --j) {
            /* Algorithm Line 10: bit <- bit j of n-1 */
            int word_idx = j / BN_BITS2;
            int bit_idx = j % BN_BITS2;
            int bit_val = (int)((w1->d[word_idx] >> bit_idx) & 1);

            /* Algorithm Line 11: CSWAP(bit, R_0, R_1) */
            ct_swap_arrays(bit_val, R0, R1, top_w);

            /* Algorithm Line 12: R_1 <- R_0 * R_1 mod n */
            ct_mont_mul(t1, R0, R1, mont, top_w, ct_tmp);
            
            /* Algorithm Line 13: R_0 <- R_0 * R_0 mod n */
            ct_mont_mul(R0, R0, R0, mont, top_w, ct_tmp);
            
            ct_bn_copy(R1, t1, top_w);
            
            /* Algorithm Line 14: CSWAP(bit, R_0, R_1) */
            ct_swap_arrays(bit_val, R0, R1, top_w);

            /* Algorithm Lines 16-18: Capture MR conditions via bitwise logic */
            int is_one = ct_bn_equal(R0, mont_one, top_w);
            int is_w_minus_1 = ct_bn_equal(R0, mont_w1, top_w);

            int is_at_s = ct_eq_int(j, s);
            int is_in_range = ct_ge_int(s, j) & ct_ge_int(j, 1);

            /* Algorithm Line 19: pass_round <- pass_round | ((j == s) & is_one) */
            pass_this_round |= (is_at_s & is_one);
            
            /* Algorithm Line 20: pass_round <- pass_round | ((1 <= j <= s) & is_minus_one) */
            pass_this_round |= (is_in_range & is_w_minus_1);
        }

        /* Algorithm Line 22: is_composite <- is_composite | ~pass_round */
        is_composite |= (1 - pass_this_round);
    }

    /* Algorithm Line 24: Return ~is_composite */
    *status = is_composite ? BN_PRIMETEST_COMPOSITE : BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;

err:
    BN_CTX_end(ctx); BN_MONT_CTX_free(mont);
    return ret;
}