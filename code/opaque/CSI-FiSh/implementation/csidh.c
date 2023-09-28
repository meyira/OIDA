
#include <string.h>
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

#include "uint.h"
#include "fp.h"
#include "mont.h"
#include "csidh.h"
#include "rng.h"
#include "classgroup.h"

/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////// CSIDH Functions from CSI-FiSh ////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

const public_key base = {{{0}}}; /* A = 0 */

void fish_csidh_private(private_key *priv)
{
    sample_from_classgroup(priv->e);
}

static bool fish_validate_rec(proj *P, proj const *A, size_t lower, size_t upper, uint_s *order, bool *is_supersingular)
{
    assert(lower < upper);

    if (upper - lower == 1) {

        /* now P is [(p+1) / l_lower] times the original random point */
        /* we only gain information if this multiple is non-zero */

        if (memcmp(&P->z, &fp_0, sizeof(fp))) {

            uint_s tmp;
            uint_set(&tmp, primes[lower]);
            xMUL(P, A, P, &tmp);

            if (memcmp(&P->z, &fp_0, sizeof(fp))) {
                /* order does not divide p+1. */
                *is_supersingular = false;
                return true;
            }

            uint_mul3_64(order, order, primes[lower]);

            if (uint_sub3(&tmp, &four_sqrt_p, order)) { /* returns borrow */
                /* order > 4 sqrt(p), hence definitely supersingular */
                *is_supersingular = true;
                return true;
            }
        }

        /* inconclusive */
        return false;
    }

    size_t mid = lower + (upper - lower + 1) / 2;

    uint_s cl = uint_1, cu = uint_1;
    for (size_t i = lower; i < mid; ++i)
        uint_mul3_64(&cu, &cu, primes[i]);
    for (size_t i = mid; i < upper; ++i)
        uint_mul3_64(&cl, &cl, primes[i]);

    proj Q;

    xMUL(&Q, A, P, &cu);
    xMUL(P, A, P, &cl);

    /* start with the right half; bigger primes help more */
    return fish_validate_rec(&Q, A, mid, upper, order, is_supersingular)
        || fish_validate_rec(P, A, lower, mid, order, is_supersingular);
}

/* never accepts invalid keys. */
bool fish_validate(public_key const *in)
{
    /* make sure the curve is nonsingular: A^2-4 != 0 */
    {
        uint_s dummy;
        if (!uint_sub3(&dummy, (uint_s *) &in->A, &p)) /* returns borrow */
            /* A >= p */
            return false;

        fp fp_pm2;
        fp_set(&fp_pm2, 2);
        if (!memcmp(&in->A, &fp_pm2, sizeof(fp)))
            /* A = 2 */
            return false;

        fp_sub3(&fp_pm2, &fp_0, &fp_pm2);
        if (!memcmp(&in->A, &fp_pm2, sizeof(fp)))
            /* A = -2 */
            return false;
    }

    proj A;
    fp_enc(&A.x, &in->A);
    A.z = fp_1;

    do {
        proj P;
        fp_random(&P.x);
        P.z = fp_1;

        /* maximal 2-power in p+1 */
        fish_xDBL(&P, &A, &P);
        fish_xDBL(&P, &A, &P);

        bool is_supersingular;
        uint_s order = uint_1;

        if (fish_validate_rec(&P, &A, 0, NUM_PRIMES, &order, &is_supersingular))
            return is_supersingular;

    /* P didn't have big enough order to prove supersingularity. */
    } while (1);
}

/* compute x^3 + Ax^2 + x */
static void montgomery_rhs(fp *rhs, fp const *A, fp const *x)
{
    fp tmp;
    *rhs = *x;
    fp_sq1(rhs);
    fp_mul3(&tmp, A, x);
    fp_add2(rhs, &tmp);
    fp_add2(rhs, &fp_1);
    fp_mul2(rhs, x);
}

static __inline__ uint64_t rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | (uint64_t) hi << 32;
}

/* totally not constant-time. */
void action(public_key *out, public_key const *in, private_key const *priv)
{
    uint_s k[2];
    uint_set(&k[0], 4); /* maximal 2-power in p+1 */
    uint_set(&k[1], 4); /* maximal 2-power in p+1 */

    uint8_t e[2][NUM_PRIMES];

    for (size_t i = 0; i < NUM_PRIMES; ++i) {

        int8_t t = (int8_t) priv->e[i] ;

        if (t > 0) {
            e[0][i] = t;
            e[1][i] = 0;
            uint_mul3_64(&k[1], &k[1], primes[i]);
        }
        else if (t < 0) {
            e[1][i] = -t;
            e[0][i] = 0;
            uint_mul3_64(&k[0], &k[0], primes[i]);
        }
        else {
            e[0][i] = 0;
            e[1][i] = 0;
            uint_mul3_64(&k[0], &k[0], primes[i]);
            uint_mul3_64(&k[1], &k[1], primes[i]);
        }
    }

    proj A;
    fp_enc(&A.x, &in->A);
    A.z = fp_1;

    bool done[2] = {false, false};

    int count = 0;

    do {

        assert(!memcmp(&A.z, &fp_1, sizeof(fp)));

        proj P;
        fp_random(&P.x);
        P.z = fp_1;

        fp rhs;
        montgomery_rhs(&rhs, &A.x, &P.x);
        bool sign = !fp_issquare(&rhs);

        if (done[sign])
            continue;
        
        count ++;

        //uint64_t T = rdtsc();

        xMUL(&P, &A, &P, &k[sign]);

        /*printf("%d , %d \n",count , rdtsc() - T);
        for(int l=0; l<NUM_PRIMES ; l++){
            printf("%2d", e[0][l]-e[1][l]);
        }
        printf("\n");*/

        done[sign] = true;

        for (size_t i = NUM_PRIMES - 1; i < NUM_PRIMES; --i) {

            if (e[sign][i]) {

                uint_s cof = uint_1;
                for (size_t j = 0; j < i; ++j)
                    if (e[sign][j])
                        uint_mul3_64(&cof, &cof, primes[j]);

                proj K;
                xMUL(&K, &A, &P, &cof);

                if (memcmp(&K.z, &fp_0, sizeof(fp))) {                    

                    // T = rdtsc();

                    fish_xISOG(&A, &P, &K, primes[i],0);

                    //printf("   i:%2d cyc:%d cyc/p:%d \n", i, rdtsc() - T, (rdtsc() - T)/primes[i]);

                    if (!--e[sign][i])
                        uint_mul3_64(&k[sign], &k[sign], primes[i]);

                }

            }

            done[sign] &= !e[sign][i];
        }

        fp_inv(&A.z);
        fp_mul2(&A.x, &A.z);
        A.z = fp_1;

    } while (!(done[0] && done[1]));

    //printf("\n");

    fp_dec(&out->A, &A.x);

}

/* includes public-key validation. */
bool fish_csidh(public_key *out, public_key const *in, private_key const *priv)
{
    if (!fish_validate(in)) {
        fp_random((fp *) &out->A);
        return false;
    }
    action(out, in, priv);
    return true;
}

/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////// CSIDH Functions from OPUS ////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
void uint_print(uint_s const *x)
{
    for (size_t i = 8*LIMBS-1; i < 8*LIMBS; --i)
        printf("%02hhx", i[(unsigned char *) x->c]);
    puts("");
}

void add_large_key(large_private_key *res, const private_key *k1){
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]+=k1->e[i];
  }
}

void sub_large_key(large_private_key *res, const private_key *k1){
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]-=k1->e[i];
  }
}
void add_key(private_key *res, const private_key *k1){
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]+=k1->e[i];
  }
}
void sub_key(private_key *res, const private_key *k1){
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]-=k1->e[i];
  }
}

/* TODO still wastes quite a bit of randomness */
__attribute__((visibility("default")))
void csidh_private(private_key *priv)
{
    memset(&priv->e, 0, sizeof(priv->e));
    for (size_t i = 0; ; ) {
        uint8_t buf[64];
        randbytes(buf, sizeof(buf));
        for (size_t j = 0; j < 2*sizeof(buf); ++j) {
            int8_t v = (buf[j/2] >> j%2*4 & 0xf);
            v = (int8_t) (v << 4) >> 4;
            if (v <= MAX_EXPONENT && v >= -MAX_EXPONENT) {
                priv->e[i++] = v;
                if (i >= NUM_PRIMES)
                    return;
            }
        }
    }
}

static bool validate_rec(bool *is_supersingular, uint_s *order, uint8_t *seen, proj *P, proj const *A, size_t lower, size_t upper)
{
    assert(lower < upper);

    if (upper - lower == 1) {

        const size_t i = lower;

        if (seen[i/8] & 1<<i%8)
            return false;

        /* now P is [(p+1) / l_lower] times the original random point */
        /* we only gain information if this multiple is non-zero */

        if (!is_infinity(P)) {

            uint_s tmp;
            uint_set(&tmp, primes[i]);
            xMUL(P, A, P, &tmp);

            if (!is_infinity(P)) {
                /* order does not divide p+1. */
                *is_supersingular = false;
                return true;
            }

            uint_mul3_64(order, order, primes[i]);
            seen[i/8] |= 1<<i%8;

            if (uint_sub3(&tmp, &four_sqrt_p, order)) { /* returns borrow */
                /* order > 4 sqrt(p), hence definitely supersingular */
                *is_supersingular = true;
                return true;
            }
        }

        /* inconclusive */
        return false;
    }

    /* TODO split according to non-seen primes rather than blindly */
    size_t mid = lower + (upper - lower + 1) / 2;

    uint_s cl = uint_1, cu = uint_1, *cc = &cu;
    for (size_t i = lower; i < upper; cc = ++i < mid ? &cu : &cl)
        if (~seen[i/8] & 1<<i%8)
            uint_mul3_64(cc, cc, primes[i]);

    proj Q;

    xMUL(&Q, A, P, &cu);
    xMUL( P, A, P, &cl);

    /* start with the right half; bigger primes help more */
    return validate_rec(is_supersingular, order, seen, &Q, A, mid, upper)
        || validate_rec(is_supersingular, order, seen,  P, A, lower, mid);
}

bool validate_basic(public_key const *in)
{
    /* make sure A < p */
    uint_s dummy;
    if (!uint_sub3(&dummy, &in->A, &p)) /* returns borrow */
        return false;

    /* make sure the curve is nonsingular: A != 2 */
    uint_s pm2;
    uint_set(&pm2, 2);
    if (uint_eq(&in->A, &pm2))
        return false;

    /* make sure the curve is nonsingular: A != -2 */
    uint_sub3(&pm2, &uint_0, &pm2);
    if (uint_eq(&in->A, &pm2))
        return false;

    return true;
}

/* includes public-key validation. */
/* totally not constant-time. */
__attribute__((visibility("default")))
bool csidh(public_key *out, public_key const *in, private_key const *priv)
{

    if (!validate_basic(in))
        goto invalid;

    int8_t es[NUM_PRIMES];
    memcpy(es, priv->e, sizeof(es));

    proj A;
    fp_enc(&A.x, &in->A);
    A.z = fp_1;

    uint_s order = uint_1;
    uint8_t seen[(NUM_PRIMES+7)/8] = {0}; /* packed bool */

    fp elligator_rand = first_elligator_rand;
    if (!fp_eq(&A.x, &fp_0))
        fp_mul2(&elligator_rand, &A.x);

    for (bool twist = false; ; ) {

        #define BATCH_SIZE 16

        uint8_t batch[(NUM_PRIMES+7)/8] = {0}; /* packed bool */
        {
            size_t sz = 0;
            for (size_t i = 0; i < NUM_PRIMES && sz < BATCH_SIZE; ++i) {
                if (twist ? (es[i] < 0) : (es[i] > 0)) {
                    batch[i/8] |= 1<<i%8;
                    ++sz;
                }
            }
            if (!sz) {
                if (twist) break;
                twist = true;
                continue;
            }
        }


        uint_s k = p_cofactor;
        for (size_t i = 0; i < NUM_PRIMES; ++i)
            if (~batch[i/8] & 1<<i%8)
                uint_mul3_64(&k, &k, primes[i]);

        assert(is_affine(&A));

        proj P = {elligator_rand, fp_1};
        if (is_twist(&P.x, &A.x) != twist) {
            fp_add2(&P.x, &A.x);
            fp_sub3(&P.x, &fp_0, &P.x);
        }

        xMUL(&P, &A, &P, &k);


        for (size_t i = NUM_PRIMES-1; i < NUM_PRIMES; --i) {

            if (~batch[i/8] & 1<<i%8) continue;

            uint_s cof = uint_1;
            for (size_t j = 0; j < i; ++j)
                if (batch[j/8] & 1<<j%8)
                    uint_mul3_64(&cof, &cof, primes[j]);

            if (uint_len(&cof) > (cost_ratio_inv_mul >> !is_affine(&A)))
                affinize(&A, &P);

            proj K;
            xMUL(&K, &A, &P, &cof);

            if (is_infinity(&K))
                continue;

            bool want = !(seen[i/8] & (1 << i%8));

            xISOG(&A, &P, &K, primes[i], want);

            if (want) {
                if (!is_infinity(&K)) goto invalid;
                uint_mul3_64(&order, &order, primes[i]);
                seen[i/8] |= 1 << i%8;
            }

            es[i] -= twist ? -1 : 1;

        }

        assert(!is_infinity(&A));

        fp_random(&elligator_rand);
        if (!fp_eq(&A.x, &fp_0)) {
            fp_sq1(&elligator_rand);
            fp_sub2(&elligator_rand, &fp_1);
            proj t = A;
            fp_mul2(&t.z, &elligator_rand);
            affinize(&A, &t);
            elligator_rand = t.x;
        }
        else
            affinize(&A, NULL);

    }

    /* public-key validation */
    {
        uint_s tmp;
        proj P;
        bool is_supersingular = uint_sub3(&tmp, &four_sqrt_p, &order); /* returns borrow */

        if (!is_supersingular) do {
            /* this happens only extremely rarely. */

            fp_random(&P.x);
            P.z = fp_1;

            xMUL(&P, &A, &P, &p_cofactor);
            xMUL(&P, &A, &P, &order);

        } while (!validate_rec(&is_supersingular, &order, seen, &P, &A, 0, NUM_PRIMES));

        if (!is_supersingular) {
invalid:
                puts("Obtained invalid curves");
            randbytes(&out->A, sizeof(out->A));
            return false;
        }
    }

    assert(is_affine(&A));
    fp_dec(&out->A, &A.x);

    return true;

}

bool large_csidh(public_key *out, public_key const *in, large_private_key const *priv)
{

  // if (!validate_basic(in))
  //     goto invalid;

  int32_t es[NUM_PRIMES];
  memcpy(es, priv->e, sizeof(es));

  proj A;
  fp_enc(&A.x, &in->A);
  A.z = fp_1;

  uint_s order = uint_1;
  uint8_t seen[(NUM_PRIMES+7)/8] = {0}; /* packed bool */

  fp elligator_rand = first_elligator_rand;
  if (!fp_eq(&A.x, &fp_0))
    fp_mul2(&elligator_rand, &A.x);

  for (bool twist = false; ; ) {

#define BATCH_SIZE 16

    uint8_t batch[(NUM_PRIMES+7)/8] = {0}; /* packed bool */
    {
      size_t sz = 0;
      for (size_t i = 0; i < NUM_PRIMES && sz < BATCH_SIZE; ++i) {
        if (twist ? (es[i] < 0) : (es[i] > 0)) {
          batch[i/8] |= 1<<i%8;
          ++sz;
        }
      }
      if (!sz) {
        if (twist) break;
        twist = true;
        continue;
      }
    }


    uint_s k = p_cofactor;
    for (size_t i = 0; i < NUM_PRIMES; ++i)
   if (~batch[i/8] & 1<<i%8)
        uint_mul3_64(&k, &k, primes[i]);

    assert(is_affine(&A));

    proj P = {elligator_rand, fp_1};
    if (is_twist(&P.x, &A.x) != twist) {
      fp_add2(&P.x, &A.x);
      fp_sub3(&P.x, &fp_0, &P.x);
    }

    xMUL(&P, &A, &P, &k);


    for (size_t i = NUM_PRIMES-1; i < NUM_PRIMES; --i) {

      if (~batch[i/8] & 1<<i%8) continue;

      uint_s cof = uint_1;
      for (size_t j = 0; j < i; ++j)
        if (batch[j/8] & 1<<j%8)
          uint_mul3_64(&cof, &cof, primes[j]);

      if (uint_len(&cof) > (cost_ratio_inv_mul >> !is_affine(&A)))
        affinize(&A, &P);

      proj K;
      xMUL(&K, &A, &P, &cof);

      if (is_infinity(&K))
        continue;

      bool want = !(seen[i/8] & (1 << i%8));

      xISOG(&A, &P, &K, primes[i], want);

      if (want) {
        if (!is_infinity(&K)) goto invalid;
        uint_mul3_64(&order, &order, primes[i]);
        seen[i/8] |= 1 << i%8;
      }

      es[i] -= twist ? -1 : 1;

    }

    assert(!is_infinity(&A));

        fp_random(&elligator_rand);
    if (!fp_eq(&A.x, &fp_0)) {
      fp_sq1(&elligator_rand);
      fp_sub2(&elligator_rand, &fp_1);
      proj t = A;
      fp_mul2(&t.z, &elligator_rand);
      affinize(&A, &t);
      elligator_rand = t.x;
    }
    else
      affinize(&A, NULL);

  }

  /* public-key validation */
  {
    uint_s tmp;
    proj P;
    bool is_supersingular = uint_sub3(&tmp, &four_sqrt_p, &order); /* returns borrow */

    if (!is_supersingular) do {
        /* this happens only extremely rarely. */

        fp_random(&P.x);
        P.z = fp_1;

        xMUL(&P, &A, &P, &p_cofactor);
        xMUL(&P, &A, &P, &order);

      } while (!validate_rec(&is_supersingular, &order, seen, &P, &A, 0, NUM_PRIMES));

    if (!is_supersingular) {
invalid:
            puts("Obtained invalid curves");
            randbytes(&out->A, sizeof(out->A));
            return false;
    }
  }

  assert(is_affine(&A));
  fp_dec(&out->A, &A.x);

  return true;

}