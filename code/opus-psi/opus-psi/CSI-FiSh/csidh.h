#ifndef CSIDH_H
#define CSIDH_H

#include <stdbool.h>

#include "p512/params.h"

typedef struct large_private_key {
    int32_t e[NUM_PRIMES]; 
} large_private_key;

typedef struct private_key {
    int8_t e[NUM_PRIMES]; /* packed int4_t */
} private_key;

typedef struct public_key {
    fp A; /* Montgomery coefficient: represents y^2 = x^3 + Ax^2 + x */
} public_key;

extern const public_key base;

void csidh_private(private_key *priv);
bool csidh(public_key *out, public_key const *in, private_key const *priv);
void action(public_key *out, public_key const *in, private_key const *priv);
void large_action(public_key *out, public_key const *in, large_private_key const *priv);

void add_large_key(large_private_key *res, const private_key *k1);

void assign_large_key(large_private_key *res, const private_key *k1);

void sub_large_key(large_private_key *res, const private_key *k1);

void negate_key(private_key *res, const private_key *k1);

void priv_print(private_key const *x);
void uint_print(uint_s const *x);
void fp_print(fp const *x);



#endif
