#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "csidh.h"
#include "opus.h"
#include "csike.h"
#include "csifish.h"
#include "opaque-common.h"

#ifdef TLS_OPAQUE
#include "openssl/ssl.h"
#endif
#include "aux_/crypto_kdf_hkdf_sha512.h"
#include <sodium.h>
#include "libkeccak.a.headers/SP800-185.h"

#define M_LEN (sizeof(PublicKeyStructure) * 2 + sizeof(SecretKeyStructure)) // Length of user envelope
#define C_LEN ((crypto_aead_aes256gcm_ABYTES) + (M_LEN))                    // Length of auth-encrypted user envelope
#define S_LEN (32)                                                          // Length of prf key 's'
#define KMAC_KEY_LEN (32)                                                   // Length of KMAC output
#define SHARED_KEY_LEN (32)
#define NUM_OPRF_KEYS ((crypto_hash_sha256_BYTES) * 8 + 1)

typedef struct PublicKeyStructure {
    public_key ek;
    unsigned char vk[PK_BYTES];
} PublicKeyStructure;

typedef struct SecretKeyStructure {
    CSIKESecretKeyPair dk;
    unsigned char sk[SK_BYTES];
} SecretKeyStructure;

typedef struct User {
  char *username;
  size_t username_len;
  PublicKeyStructure Ipks;
  SecretKeyStructure Isks;
  PublicKeyStructure Ipkc;
  unsigned char c[C_LEN];
  unsigned char n[crypto_aead_aes256gcm_NPUBBYTES];
  unsigned char s[S_LEN];
#ifndef NR_OPRF
  private_key oprf_keys[NUM_OPRF_KEYS];
#else
  unsigned char seed[SEED_BYTES*NUM_OPRF_KEYS];
#endif
} User;

typedef struct UserDataBase {
  User *users;
  size_t size;
  size_t indx;
} UserDataBase;

#ifdef NR_OPRF
void kat(const unsigned char *seed, const unsigned char *hashed_pw, public_key *out);
int nr_oprf_c(int socket, const unsigned char *in, size_t in_len, public_key *out);
int nr_oprf_s(int socket, const unsigned char *seed, size_t in_len);
#endif

void prf(const unsigned char key[S_LEN], unsigned char *out, size_t out_len,
  const unsigned char *in, size_t in_len, unsigned char *cstm, size_t cstm_len);

int init_list(UserDataBase *db, size_t size);
int add_user(UserDataBase *db, User *to_add);
User *lookup(const UserDataBase *db, const char *username);
void destroy_list(UserDataBase *db);

#ifndef TLS_OPAQUE
// Normal PQ-OPAQUE functions using sockets
int user_registration_c(int sock, const char *username, size_t username_len, const char *pw, size_t pw_len);
int user_registration_s(int sock, UserDataBase *db);
#else
// PQ-OPAQUE functions using TLS connection
int user_registration_c(SSL *ssl, const char *username, size_t username_len, const char *pw, size_t pw_len);
int user_registration_s(SSL *ssl, UserDataBase *db);
#endif

// OPRF in TLS OPAQUE mode still performs OPRF over socket, not TLS connection (for simplicity, extra security not needed anyways)
int oprf_c(int sock, const char *pw, size_t pw_len, uint8_t rw[crypto_kdf_hkdf_sha512_KEYBYTES]);
int oprf_s(int sock, const private_key *oprf_keys, const unsigned char *seed);
int session_c(int sock, const char *username, size_t username_len, const char *pw, size_t pw_len, unsigned char *shared_key);
int session_s(int sock, UserDataBase *db, unsigned char *shared_key);
void oprf_finalize(const char *pw, const uint16_t pw_len, const public_key *oprf_out, uint8_t *rw);

#ifdef TLS_OPAQUE
int SSL_read_all(SSL *ssl, void *buf, int num);
#endif

#endif
