#include <assert.h>
#include "csike.h"

void G(const uint8_t G_in[CSIDH_NUM_BYTES + CSIDH_PK_LEN], private_key *r) {
  uint8_t G_out[CSIDH_NUM_BYTES];
  unsigned char name[] = "";
  unsigned char cstm_g[] = "G";
  size_t count = 0;
  uint8_t in[CSIDH_NUM_BYTES + CSIDH_PK_LEN + sizeof(uint8_t)];
  memcpy(in, G_in, CSIDH_NUM_BYTES + CSIDH_PK_LEN);
  // Use an additional counter to prevent cSHAKE from producing the same output every iteration
  in[CSIDH_NUM_BYTES + CSIDH_PK_LEN] = 0;

  while(1) {
    assert(in[CSIDH_NUM_BYTES + CSIDH_PK_LEN] != 255);
    cSHAKE256(in, (CSIDH_NUM_BYTES + CSIDH_PK_LEN + sizeof(uint8_t)) * 8, G_out, sizeof(G_out) * 8, name, sizeof(name) * 8,
      cstm_g, sizeof(cstm_g) * 8);
    in[CSIDH_NUM_BYTES + CSIDH_PK_LEN]++;
      
    for(size_t i = 0; i < (2 * CSIDH_NUM_BYTES); i++) {
      int8_t val = (G_out[i / 2] >> (i % 2) * 4) & 0xF;
      if(val <= MAX_EXPONENT && val >= -MAX_EXPONENT) {
        r->e[count++] = val;
        if(count == NUM_PRIMES) return;
      } 
    }
  }
}

void csike_keygen(public_key *pk, CSIKESecretKeyPair *sk) {
  if(!pk || !sk) return;

  csidh_private(&sk->s_csidh);
  csidh(pk, &base, &sk->s_csidh);

  randbytes(sk->s, sizeof(sk->s));
}

void csike_encap(const public_key *pk,
  uint8_t c[CSIDH_PK_LEN + CSIDH_NUM_BYTES], uint8_t ks[CSIDH_NUM_BYTES], uint8_t tau[CSIDH_NUM_BYTES]) {
  if(!pk || !c || !ks || !tau) return;

  // G_in = m || pk    
  uint8_t G_in[CSIDH_NUM_BYTES + CSIDH_PK_LEN];
  randbytes(G_in, CSIDH_NUM_BYTES);
  memcpy(G_in + CSIDH_NUM_BYTES, pk, CSIDH_PK_LEN);

  // r = G(m, pk)
  private_key r;
  G(G_in, &r);

  // c = R || m xor F(S)
  public_key R, S;
  csidh(&R, &base, &r);
  csidh(&S, pk, &r);
  memcpy(c, &R, CSIDH_PK_LEN);

  // m xor F(S)
  uint8_t fs[CSIDH_NUM_BYTES];
  unsigned char name[] = "";
  unsigned char cstm_f[] = "F";
  cSHAKE256((uint8_t *) &S, CSIDH_PK_LEN * 8, fs, sizeof(fs) * 8, name, sizeof(name) * 8,
    cstm_f, sizeof(cstm_f) * 8);
  for(size_t i = 0; i < CSIDH_NUM_BYTES; i++) {
    c[i + CSIDH_PK_LEN] = G_in[i] ^ fs[i];
  }

  // kdf_in = m || c
  uint8_t kdf_in[2 * CSIDH_NUM_BYTES + CSIDH_PK_LEN];
  memcpy(kdf_in, G_in, CSIDH_NUM_BYTES);
  memcpy(kdf_in + CSIDH_NUM_BYTES, c, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
    
  // (ks, ka) = KDF(m, c)
  uint8_t keypair[2 * CSIDH_NUM_BYTES];
  unsigned char cstm_kdf[] = "KDF";
  cSHAKE256(kdf_in, sizeof(kdf_in) * 8, keypair, sizeof(keypair) * 8, name, sizeof(name) * 8,
    cstm_kdf, sizeof(cstm_kdf) * 8);
  memcpy(ks, keypair, CSIDH_NUM_BYTES);
    
  // h_in = ka || c
  uint8_t h_in[2 * CSIDH_NUM_BYTES + CSIDH_PK_LEN];
  memcpy(h_in, keypair + CSIDH_NUM_BYTES, CSIDH_NUM_BYTES);
  memcpy(h_in + CSIDH_NUM_BYTES, c, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
    
  // tau = H(ka, C)
  unsigned char cstm_h[] = "H";
  cSHAKE256(h_in, sizeof(h_in) * 8, tau, CSIDH_NUM_BYTES * 8, name, sizeof(name) * 8,
    cstm_h, sizeof(cstm_h) * 8); 
}

void csike_decap(const uint8_t c[CSIDH_PK_LEN + CSIDH_NUM_BYTES], const uint8_t tau[CSIDH_NUM_BYTES], const CSIKESecretKeyPair *sk,
  uint8_t ks[CSIDH_NUM_BYTES]) {
  if(!c || !tau || !sk || !ks) return;
    
  public_key R, S;
  memcpy(&R, c, CSIDH_PK_LEN);
  csidh(&S, &R, &sk->s_csidh);

  uint8_t fs[CSIDH_NUM_BYTES];
  unsigned char name[] = "";
  unsigned char cstm_f[] = "F";
  cSHAKE256((uint8_t *) &S, CSIDH_PK_LEN * 8, fs, sizeof(fs) * 8, name, sizeof(name) * 8,
    cstm_f, sizeof(cstm_f) * 8);
    
  // m = c xor F(S)
  uint8_t m[CSIDH_NUM_BYTES];
  for(size_t i = 0; i < CSIDH_NUM_BYTES; i++) {
    m[i] = c[i + CSIDH_PK_LEN] ^ fs[i];
  }
    
  // kdf_in = m || c
  uint8_t kdf_in[2 * CSIDH_NUM_BYTES + CSIDH_PK_LEN];
  memcpy(kdf_in, m, CSIDH_NUM_BYTES);
  memcpy(kdf_in + CSIDH_NUM_BYTES, c, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
    
  // (ks, ka) = KDF(m, c)
  uint8_t keypair[2 * CSIDH_NUM_BYTES];
  unsigned char cstm_kdf[] = "KDF";
  cSHAKE256(kdf_in, sizeof(kdf_in) * 8, keypair, sizeof(keypair) * 8, name, sizeof(name) * 8,
    cstm_kdf, sizeof(cstm_kdf) * 8);
    
  // h_in = ka || c
  uint8_t h_in[2 * CSIDH_NUM_BYTES + CSIDH_PK_LEN];
  memcpy(h_in, keypair + CSIDH_NUM_BYTES, CSIDH_NUM_BYTES);
  memcpy(h_in + CSIDH_NUM_BYTES, c, CSIDH_PK_LEN + CSIDH_NUM_BYTES);

  // h_out = H(ka, c)
  uint8_t h_out[CSIDH_NUM_BYTES];
  unsigned char cstm_h[] = "H";
  cSHAKE256(h_in, sizeof(h_in) * 8, h_out, sizeof(h_out) * 8, name, sizeof(name) * 8,
    cstm_h, sizeof(cstm_h) * 8);
    
  // if tau != H(ka, c) then (ks, ka) = KDF(s, c)
  if(memcmp(tau, h_out, CSIDH_NUM_BYTES) != 0) {
    memcpy(kdf_in, sk->s, CSIDH_NUM_BYTES);
    cSHAKE256(kdf_in, sizeof(kdf_in) * 8, keypair, sizeof(keypair) * 8, name, sizeof(name) * 8,
      cstm_kdf, sizeof(cstm_kdf) * 8);
  }

  memcpy(ks, keypair, CSIDH_NUM_BYTES);
}
