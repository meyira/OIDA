#ifndef CSIKE_H
#define CSIKE_H

#include "string.h"

#include "csidh.h"
#include "rng.h"
#include "libkeccak.a.headers/SP800-185.h"

#define CSIDH_NUM_BYTES (32)
#define CSIDH_PK_LEN ((LIMBS) * 8)
#define CSIDH_SK_LEN (NUM_PRIMES)

typedef struct SecretKeyPair {
    uint8_t s[CSIDH_NUM_BYTES];
    private_key s_csidh;
} CSIKESecretKeyPair;

// CSIKE is IND-CCA secure according to its paper
// F: {0, 1}* -> {0, 1}^λ
// H: {0, 1}* -> {0, 1}^λ
// G: {0, 1}* -> \mathcal{G}
// KDF: {0, 1}* -> {0, 1}^(2λ)
void csike_keygen(public_key *pk, CSIKESecretKeyPair *sk);
void csike_encap(const public_key *pk, uint8_t c[CSIDH_PK_LEN + CSIDH_NUM_BYTES],
  uint8_t ks[CSIDH_NUM_BYTES], uint8_t tau[CSIDH_NUM_BYTES]);
void csike_decap(const uint8_t c[CSIDH_PK_LEN + CSIDH_NUM_BYTES], const uint8_t tau[CSIDH_NUM_BYTES],
  const CSIKESecretKeyPair *sk, uint8_t ks[CSIDH_NUM_BYTES]);

#endif
