#ifndef CSIDH_H
#define CSIDH_H

#include <stdbool.h>

#include "p512/params.h"

typedef struct private_key {
    int8_t e[NUM_PRIMES];
} private_key;
typedef struct large_private_key {
  int32_t e[NUM_PRIMES];
} large_private_key;



typedef struct public_key {
    uint_s A; /* Montgomery coefficient: represents y^2 = x^3 + Ax^2 + x */
} public_key;

extern const public_key base;

void csidh_private(private_key *priv);
bool csidh(public_key *out, public_key const *in, private_key const *priv);
void uint_print(uint_s const *x);

//////////////////// NEW FUNCTIONS ///////////////////
bool large_csidh(public_key *out, public_key const *in, large_private_key const *priv);

void add_large_key(large_private_key *res, const private_key *k1);
void sub_large_key(large_private_key *res, const private_key *k1);
void add_key(private_key *res, const private_key *k1);
void sub_key(private_key *res, const private_key *k1);


#endif
