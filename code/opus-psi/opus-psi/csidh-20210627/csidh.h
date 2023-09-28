#ifndef CSIDH_H
#define CSIDH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <string.h>

#include "params.h"

typedef struct large_private_key {
  int32_t e[NUM_PRIMES];
} large_private_key;

typedef struct private_key {
    int8_t e[NUM_PRIMES];
} private_key;

typedef struct public_key {
  limbs A; /* Montgomery coefficient: represents y^2 = x^3 + Ax^2 + x */
} public_key;

extern const public_key base;

void add_large_key(large_private_key *res, const private_key k1);
void sub_large_key(large_private_key *res, const private_key k1);
void add_key(private_key *res, const private_key k1);
void csidh_private(private_key *priv);
bool csidh(public_key *out, public_key const *in, private_key const *priv);
bool large_csidh(public_key *out, public_key const *in, large_private_key const *priv);
bool validate_basic(public_key const *in);


void uint_print(limbs const *x);
void priv_print(private_key const *k);

#ifdef __cplusplus
}
#endif


#endif
