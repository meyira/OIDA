#include "utils.h"

void print_hex(const unsigned char *arr, size_t len) {
  for(size_t i = 0; i < len; i++) {
    printf("%02x", arr[i]);
  }
  printf("\n");
}

// Using KMAC256 with a variable output is ok, since we use it as a PRF and not a MAC
void prf(const unsigned char key[S_LEN], unsigned char *out, size_t out_len,
  const unsigned char *in, size_t in_len, unsigned char *cstm, size_t cstm_len) {
  KMAC256(key, S_LEN * 8, in, in_len * 8, out, out_len * 8, cstm, cstm_len * 8);
}

int init_list(UserDataBase *db, size_t size) {
  if(!db) return -1;

  if(db->users) {
    printf("List already initialized\n");
    return -1;
  }

  db->users = calloc(size, sizeof(User));
  if(!db->users) {
    printf("Calloc failed\n");
    return -1;
  }
  db->size = size;
  db->indx = 0;

  return 0;
}

int add_user(UserDataBase *db, User *to_add) {
  if(!db || !to_add) return -1;

  if(db->indx == db->size) {
    size_t new_size = 0;
    if(__builtin_mul_overflow(db->size, 2, &new_size)) {
      printf("Overflow\n");
      return -1;
    }

    User *temp = realloc(db->users, new_size * sizeof(User));
    if(!temp) {
      printf("Realloc failed\n");
      return -1;
    }

    db->users = temp;
    memset(db->users + db->size, 0, db->size);
    db->size = new_size;
  }

  memcpy(&db->users[db->indx++], to_add, sizeof(User));
  return 0;
}

User *lookup(const UserDataBase *db, const char *username) {
  if(!db || !username) return 0;
  User *user = 0;

  for(size_t i = 0; i < db->indx; i++) {
    if(strcmp(db->users[i].username, username) == 0) {
      user = &db->users[i];
      break;
    }
  }

  return user;
}

void destroy_list(UserDataBase *db) {
  if(!db) return;

  for(size_t i = 0; i < db->indx; i++) {
    User *curr_user = &db->users[i];
    free(curr_user->username);
    memset(curr_user, 0, sizeof(User));
  }
  
  free(db->users);
  db->users = 0;
  db->size = 0;
  db->indx = 0;
}

#ifndef TLS_OPAQUE
int user_registration_c(int sock, const char *username, size_t username_len, const char *pw, size_t pw_len) {
#else
int user_registration_c(SSL *ssl, const char *username, size_t username_len, const char *pw, size_t pw_len) {
#endif
  // Send username len + username (without 0 byte)
#ifndef TLS_OPAQUE
  send(sock, &username_len, sizeof(size_t), 0);
  send(sock, username, username_len, 0);
#else
  if(SSL_write(ssl, &username_len, sizeof(size_t)) <= 0) return -1;
  if(SSL_write(ssl, username, username_len) <= 0) return -1;
#endif

  uint8_t rw[crypto_kdf_hkdf_sha512_KEYBYTES] = {0};
#ifndef TLS_OPAQUE
  if(oprf_c(sock, pw, pw_len, rw) != 0) return -1;
#else
  if(oprf_c(SSL_get_fd(ssl), pw, pw_len, rw) != 0) return -1;
#endif

  PublicKeyStructure Ipkc;
  SecretKeyStructure Iskc; 
  // (ekC, dKC) <- KEM.KeyGen()
  csike_keygen(&Ipkc.ek, &Iskc.dk);
  // (vkC, skC) <- SIG.KeyGen()
  csifish_keygen(Ipkc.vk, Iskc.sk);

  // <-- (ekS, vkS)
  PublicKeyStructure Ipks;
#ifndef TLS_OPAQUE
  if(read_len(sock, (unsigned char *) &Ipks, sizeof(PublicKeyStructure), "Ipks") != 0) return -1;
#else
  if(SSL_read_all(ssl, &Ipks, sizeof(PublicKeyStructure)) != 0) return -1;
#endif
  
  // c = AuthEnc_rw(lt_pk_c || lt_pk_s || lt_sk_c, n)
  // Use AES256-GCM without AD
  unsigned char m[M_LEN];
  memcpy(m, &Ipkc, sizeof(PublicKeyStructure));
  memcpy(m + sizeof(PublicKeyStructure), &Ipks, sizeof(PublicKeyStructure));
  memcpy(m + sizeof(PublicKeyStructure) * 2, &Iskc, sizeof(SecretKeyStructure));
  unsigned char n[crypto_aead_aes256gcm_NPUBBYTES]; 
  randombytes_buf(n, crypto_aead_aes256gcm_NPUBBYTES);
  unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  memcpy(key, rw, crypto_aead_aes256gcm_KEYBYTES);
  unsigned char c[C_LEN];
  unsigned long long c_len;
  crypto_aead_aes256gcm_encrypt(c, &c_len, m, M_LEN, 0, 0, 0, n, key);
  assert(c_len == C_LEN);
  
  // --> c, n, (ekC, vkC)
#ifndef TLS_OPAQUE
  send(sock, c, sizeof(c), 0);
  send(sock, n, crypto_aead_aes256gcm_NPUBBYTES, 0);
  send(sock, &Ipkc, sizeof(PublicKeyStructure), 0);
#else
  if(SSL_write(ssl, c, sizeof(c)) <= 0) return -1;
  if(SSL_write(ssl, n, crypto_aead_aes256gcm_NPUBBYTES) <= 0) return -1;
  if(SSL_write(ssl, &Ipkc, sizeof(PublicKeyStructure)) <= 0) return -1;
#endif

  return 0;
}

int session_c(int sock, const char *username, size_t username_len, const char *pw, size_t pw_len, unsigned char *shared_key) {
  // Send username len + username (without 0 byte)
  send(sock, &username_len, sizeof(size_t), 0);
  send(sock, username, username_len, 0);

  uint8_t rw[crypto_kdf_hkdf_sha512_KEYBYTES] = {0};
  if(oprf_c(sock, pw, pw_len, rw) != 0) return -1;
  
  public_key ekT;
  CSIKESecretKeyPair dkT;
  // (ekT, dkT) <- KEM.KeyGen()
  csike_keygen(&ekT, &dkT);
  
  // <-- c, n
  unsigned char c[C_LEN];
  unsigned char n[crypto_aead_aes256gcm_NPUBBYTES];
  if(read_len(sock, c, C_LEN, "c") != 0) return -1;
  if(read_len(sock, n, crypto_aead_aes256gcm_NPUBBYTES, "n") != 0) return -1;
  
  // (lt_pk_c || lt_pk_s || lt_sk_c) = AuthDec_rw(c, n)
  unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  memcpy(key, rw, crypto_aead_aes256gcm_KEYBYTES);
  unsigned char m[M_LEN];
  unsigned long long m_len;
  if(crypto_aead_aes256gcm_decrypt(m, &m_len, 0, c, C_LEN, 0, 0, n, key) != 0) {
    printf("Tag validation failed: Password might not be correct\n");
    return -1;
  }
  assert(m_len == M_LEN);
  
  PublicKeyStructure Ipkc, Ipks;
  SecretKeyStructure Iskc;
  memcpy(&Ipkc, m, sizeof(PublicKeyStructure));
  memcpy(&Ipks, m + sizeof(PublicKeyStructure), sizeof(PublicKeyStructure));
  memcpy(&Iskc, m + sizeof(PublicKeyStructure) * 2, sizeof(SecretKeyStructure));
  
  // σ_c <- SIG.Sign(skC, ekT)
  uint8_t σ_c[SIG_BYTES];
  size_t sig_len;
  csifish_sign(Iskc.sk, (unsigned char *) ekT.A.c, sizeof(public_key), σ_c, &sig_len);
  assert(sig_len == SIG_BYTES);
  
  // --> ekT, σ_c
  send(sock, &ekT, sizeof(public_key), 0);
  send(sock, σ_c, sig_len, 0);
  
  // <-- C, C_T, τ, τ_T, b, s 
  unsigned char C[CSIDH_PK_LEN + CSIDH_NUM_BYTES];
  unsigned char C_T[CSIDH_PK_LEN + CSIDH_NUM_BYTES];
  unsigned char τ[CSIDH_NUM_BYTES];
  unsigned char τ_T[CSIDH_NUM_BYTES];
  unsigned char b[SIG_BYTES];
  unsigned char s[S_LEN];
  if(read_len(sock, C, sizeof(C), "C") != 0) return -1;
  if(read_len(sock, C_T, sizeof(C_T), "C_T") != 0) return -1;
  if(read_len(sock, τ, sizeof(τ), "τ") != 0) return -1;
  if(read_len(sock, τ_T, sizeof(τ_T), "τ_T") != 0) return -1;
  if(read_len(sock, b, sizeof(b), "b") != 0) return -1;
  if(read_len(sock, s, sizeof(s), "s") != 0) return -1;

  // K <- KEM.Decap(dkC, C, τ)
  // K_T <- KEM.Decap(dkT, C_T, τ_T)
  unsigned char K[CSIDH_NUM_BYTES];
  unsigned char K_T[CSIDH_NUM_BYTES];
  csike_decap(C, τ, &Iskc.dk, K);
  csike_decap(C_T, τ_T, &dkT, K_T);
  
#ifdef DEBUG
  debug_print("K", K, CSIDH_NUM_BYTES);
  debug_print("K_T", K_T, CSIDH_NUM_BYTES);
#endif

  // K1 <- Ext_s(K); K2 <- Ext_s(K_T)
  unsigned char K1[KMAC_KEY_LEN];
  unsigned char K2[KMAC_KEY_LEN];
  unsigned char cstm_ext[] = "Ext_s";
  prf(s, K1, KMAC_KEY_LEN, K,   CSIDH_NUM_BYTES, cstm_ext, sizeof(cstm_ext));
  prf(s, K2, KMAC_KEY_LEN, K_T, CSIDH_NUM_BYTES, cstm_ext, sizeof(cstm_ext));

#ifdef DEBUG 
  debug_print("K1", K1, KMAC_KEY_LEN);
  debug_print("K2", K2, KMAC_KEY_LEN);
#endif

  // sid = ClientUsername || ServerHostname || Ipk_C || Ipk_C || ekT || C || C_T
  const char server_hostname[] = "server";
  size_t sid_len = username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2 + sizeof(public_key) + (CSIDH_PK_LEN + CSIDH_NUM_BYTES) * 2;
  unsigned char *sid = calloc(sid_len, sizeof(char));
  if(!sid) {
    printf("Calloc failed\n");
    return -1;
  }
  memcpy(sid, username, username_len);
  memcpy(sid + username_len, server_hostname, sizeof(server_hostname));
  memcpy(sid + username_len + sizeof(server_hostname), &Ipkc, sizeof(PublicKeyStructure));
  memcpy(sid + username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure), &Ipks, sizeof(PublicKeyStructure));
  memcpy(sid + username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2, &ekT, sizeof(public_key));
  memcpy(sid + username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2 + sizeof(public_key), C, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
  memcpy(sid + username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2 + sizeof(public_key) + CSIDH_PK_LEN + CSIDH_NUM_BYTES, C_T, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
  
  unsigned char FK1[SHARED_KEY_LEN + SIG_BYTES];
  unsigned char FK2[SHARED_KEY_LEN + SIG_BYTES];
  unsigned char cstm_f[] = "F";
  prf(K1, FK1, sizeof(FK1), sid, sizeof(sid), cstm_f, sizeof(cstm_f));
  prf(K2, FK2, sizeof(FK2), sid, sizeof(sid), cstm_f, sizeof(cstm_f)); 
  unsigned char keypair[SHARED_KEY_LEN + SIG_BYTES];
  unsigned char *k = keypair + SHARED_KEY_LEN;
  for(size_t i = 0; i < (SHARED_KEY_LEN + SIG_BYTES); i++) {
    keypair[i] = FK1[i] ^ FK2[i];
  }
  memcpy(shared_key, keypair, SHARED_KEY_LEN);
  
#ifdef DEBUG
  debug_print("FK1", FK1, SHARED_KEY_LEN + SIG_BYTES);
  debug_print("FK2", FK2, SHARED_KEY_LEN + SIG_BYTES);
#endif

  unsigned char σ[SIG_BYTES];
  for(size_t i = 0; i < SIG_BYTES; i++) {
    σ[i] = b[i] ^ k[i];
  }
  
#ifdef DEBUG
  debug_print("b", b, SIG_BYTES);
  debug_print("k", k, SIG_BYTES);
#endif
  
  if(csifish_verify(Ipks.vk, sid, sizeof(sid), σ, SIG_BYTES) != 1) {
    printf("Client σ verification failed\n");
    return -1;
  }
  
  return 0;
}

#ifndef TLS_OPAQUE
int user_registration_s(int sock, UserDataBase *db) {
#else
int user_registration_s(SSL *ssl, UserDataBase *db) {
#endif
  char *username = 0;

  // Read length of username
  size_t username_len = 0;
#ifndef TLS_OPAQUE
  if(read_len(sock, (unsigned char *) &username_len, sizeof(size_t), "username len") != 0) return -1;
#else
  if(SSL_read_all(ssl, &username_len, sizeof(size_t)) != 0) return -1;
#endif
  username = calloc(username_len + 1, sizeof(char));
  if(!username) {
    printf("Calloc failed\n");
    goto cleanup;
  }

  // Read username
#ifndef TLS_OPAQUE
  if(read_len(sock, (unsigned char *) username, username_len, "username") != 0) goto cleanup;
#else
  if(SSL_read_all(ssl, username, username_len) != 0) goto cleanup;
#endif
  username[username_len] = 0;
  
  // Check if user already registered
  if(lookup(db, username) != 0) {
    printf("Username already registered\n");
    goto cleanup;
  }
  
  User new_user = {0};
  // Initialize user specific oprf keys
#ifndef NR_OPRF
  for(size_t i = 0; i < NUM_OPRF_KEYS; i++) {
    csidh_private(&new_user.oprf_keys[i]);
  }
#else
  RAND_bytes(new_user.seed, SEED_BYTES*NUM_OPRF_KEYS);
#endif

  // OPRF evaluation
#ifndef NR_OPRF
  #ifndef TLS_OPAQUE
  if(oprf_s(sock, new_user.oprf_keys, 0)) goto cleanup;
  #else
  if(oprf_s(SSL_get_fd(ssl), new_user.oprf_keys, 0)) goto cleanup;
  #endif
#else
  #ifndef TLS_OPAQUE
  if(oprf_s(sock, 0, new_user.seed)) goto cleanup;
  #else
  if(oprf_s(SSL_get_fd(ssl), 0, new_user.seed)) goto cleanup;
  #endif
#endif

  PublicKeyStructure Ipks;
  SecretKeyStructure Isks;
  PublicKeyStructure Ipkc;
  
  // (ekS, dkS) <- KEM.KeyGen()
  csike_keygen(&Ipks.ek, &Isks.dk);
  // (vkS, skS) <- SIG.KeyGen()
  csifish_keygen(Ipks.vk, Isks.sk);
  
  // <-- (ekS, vkS)
#ifndef TLS_OPAQUE
  send(sock, &Ipks, sizeof(PublicKeyStructure), 0);
#else
  if(SSL_write(ssl, &Ipks, sizeof(PublicKeyStructure)) <= 0) goto cleanup;
#endif
  
  unsigned char c[C_LEN];
  unsigned char n[crypto_aead_aes256gcm_NPUBBYTES];
  unsigned char s[S_LEN];
  
  // --> c, n, (ekC, vkC)
#ifndef TLS_OPAQUE
  if(read_len(sock, c, C_LEN, "c") != 0) goto cleanup;
  if(read_len(sock, n, crypto_aead_aes256gcm_NPUBBYTES, "n") != 0) goto cleanup;
  if(read_len(sock, (unsigned char *) &Ipkc, sizeof(PublicKeyStructure), "Ipkc") != 0) goto cleanup;
#else
  if(SSL_read_all(ssl, c, C_LEN) != 0) goto cleanup;
  if(SSL_read_all(ssl, n, crypto_aead_aes256gcm_NPUBBYTES) != 0) goto cleanup;
  if(SSL_read_all(ssl, &Ipkc, sizeof(PublicKeyStructure)) != 0) goto cleanup;
#endif
  
  // s <- {0, 1}^256
  randombytes_buf(s, S_LEN);

  // Add user
  new_user.username = username;
  new_user.username_len = username_len;
  memcpy(&new_user.Ipks, &Ipks, sizeof(PublicKeyStructure));
  memcpy(&new_user.Isks, &Isks, sizeof(SecretKeyStructure));
  memcpy(&new_user.Ipkc, &Ipkc, sizeof(PublicKeyStructure));
  memcpy(&new_user.c, c, C_LEN);
  memcpy(&new_user.n, n, crypto_aead_aes256gcm_NPUBBYTES);
  memcpy(&new_user.s, s, S_LEN);
  add_user(db, &new_user);
  return 0;
  
cleanup:
  if(username) free(username);
  memset(&new_user, 0, sizeof(User));
  return -1;
}

int session_s(int sock, UserDataBase *db, unsigned char *shared_key) {
  char *username = 0;
  unsigned char *sid = 0;

  size_t username_len = 0;
  if(read_len(sock, (unsigned char *) &username_len, sizeof(size_t), "username len") != 0) return -1;
  username = calloc(username_len + 1, sizeof(char));
  if(!username) {
    printf("Calloc failed\n");
    return -1;
  }
  
  int ret = -1;
  if(read_len(sock, (unsigned char *) username, username_len, "username") != 0) goto cleanup;
  username[username_len] = 0; 
  User *user = lookup(db, username);
  if(!user) {
    printf("User does not exist\n");
    goto cleanup;
  }

#ifndef NR_OPRF
  if(oprf_s(sock, user->oprf_keys, 0 ) != 0) goto cleanup;
#else
  if(oprf_s(sock, 0, user->seed)) goto cleanup;
#endif

  // <-- c, n
  send(sock, user->c, C_LEN, 0);
  send(sock, user->n, crypto_aead_aes256gcm_NPUBBYTES, 0);
  
  // --> ekT, σ_c
  public_key ekT;
  unsigned char σ_c[SIG_BYTES];
  if(read_len(sock, (unsigned char *) &ekT, sizeof(public_key), "ekT") != 0) goto cleanup;
  if(read_len(sock, σ_c, SIG_BYTES, "σ_c") != 0) goto cleanup;
  
  // SIG.Verify(vkC, ekT, σ_c) == 1
  if(csifish_verify(user->Ipkc.vk, (unsigned char *) ekT.A.c, sizeof(public_key), σ_c, SIG_BYTES) != 1) {
    printf("Server Signature Verification failed\n");
    return -1;
  }

  // (K, C, τ) <- KEM.Encap(ekC)
  unsigned char K[CSIDH_NUM_BYTES];
  unsigned char C[CSIDH_PK_LEN + CSIDH_NUM_BYTES];
  unsigned char τ[CSIDH_NUM_BYTES];
  csike_encap(&user->Ipkc.ek, C, K, τ);

  // (K_T, C_T, τ_T) <- KEM.Encap(ekT)
  unsigned char K_T[CSIDH_NUM_BYTES];
  unsigned char C_T[CSIDH_PK_LEN + CSIDH_NUM_BYTES];
  unsigned char τ_T[CSIDH_NUM_BYTES];
  csike_encap(&ekT, C_T, K_T, τ_T);
  
#ifdef DEBUG
  debug_print("K", K, CSIDH_NUM_BYTES);
  debug_print("K_T", K_T, CSIDH_NUM_BYTES);
#endif
  
  // K1 <- Ext_s(K); K2 <- Ext_s(K_T)
  unsigned char K1[KMAC_KEY_LEN];
  unsigned char K2[KMAC_KEY_LEN];
  unsigned char cstm_ext[] = "Ext_s";
  prf(user->s, K1, KMAC_KEY_LEN, K,   CSIDH_NUM_BYTES, cstm_ext, sizeof(cstm_ext));
  prf(user->s, K2, KMAC_KEY_LEN, K_T, CSIDH_NUM_BYTES, cstm_ext, sizeof(cstm_ext));

#ifdef DEBUG
  debug_print("K1", K1, KMAC_KEY_LEN);
  debug_print("K2", K2, KMAC_KEY_LEN);
#endif
  
  // sid = ClientUsername || ServerHostname || Ipk_C || Ipk_C || ekT || C || C_T
  const char server_hostname[] = "server";
  size_t sid_len = user->username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2 + sizeof(public_key) + (CSIDH_PK_LEN + CSIDH_NUM_BYTES) * 2;
  sid = calloc(sid_len, sizeof(char));
  if(!sid) {
    printf("Calloc failed\n");
    goto cleanup;
  }
  memcpy(sid, user->username, user->username_len);
  memcpy(sid + user->username_len, server_hostname, sizeof(server_hostname));
  memcpy(sid + user->username_len + sizeof(server_hostname), &user->Ipkc, sizeof(PublicKeyStructure));
  memcpy(sid + user->username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure), &user->Ipks, sizeof(PublicKeyStructure));
  memcpy(sid + user->username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2, &ekT, sizeof(public_key));
  memcpy(sid + user->username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2 + sizeof(public_key), C, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
  memcpy(sid + user->username_len + sizeof(server_hostname) + sizeof(PublicKeyStructure) * 2 + sizeof(public_key) + CSIDH_PK_LEN + CSIDH_NUM_BYTES, C_T, CSIDH_PK_LEN + CSIDH_NUM_BYTES);
  
  // k_S || k <- FK1(sid) xor FK2(sid)
  unsigned char FK1[SHARED_KEY_LEN + SIG_BYTES];
  unsigned char FK2[SHARED_KEY_LEN + SIG_BYTES];
  unsigned char cstm_f[] = "F";
  prf(K1, FK1, sizeof(FK1), sid, sizeof(sid), cstm_f, sizeof(cstm_f));
  prf(K2, FK2, sizeof(FK2), sid, sizeof(sid), cstm_f, sizeof(cstm_f));
  unsigned char keypair[SHARED_KEY_LEN + SIG_BYTES];
  unsigned char *k = keypair + SHARED_KEY_LEN;
  for(size_t i = 0; i < (SHARED_KEY_LEN + SIG_BYTES); i++) {
    keypair[i] = FK1[i] ^ FK2[i];
  }
  memcpy(shared_key, keypair, SHARED_KEY_LEN);
  
#ifdef DEBUG
  debug_print("FK1", FK1, SHARED_KEY_LEN + SIG_BYTES);
  debug_print("FK2", FK2, SHARED_KEY_LEN + SIG_BYTES);
#endif
  
  // σ <- SIG.Sign(skS, sid)
  unsigned char σ[SIG_BYTES];
  size_t sig_len;
  csifish_sign(user->Isks.sk, sid, sizeof(sid), σ, &sig_len);
  assert(sig_len == SIG_BYTES);
  
  // b <- σ ^ k
  unsigned char b[SIG_BYTES];
  for(size_t i = 0; i < SIG_BYTES; i++) {
    b[i] = σ[i] ^ k[i];
  }
  
#ifdef DEBUG
  debug_print("b", b, SIG_BYTES);
  debug_print("k", k, SIG_BYTES);
#endif
  
  // <-- C, C_T, τ, τ_T, b, s
  send(sock, C, sizeof(C), 0);
  send(sock, C_T, sizeof(C_T), 0);
  send(sock, τ, sizeof(τ), 0);
  send(sock, τ_T, sizeof(τ_T), 0);
  send(sock, b, sizeof(b), 0);
  send(sock, user->s, sizeof(user->s), 0);
  ret = 0;

cleanup:
  if(username) free(username);
  if(sid) free(sid);
  return ret;
}

int oprf_c(int sock, const char *pw, size_t pw_len, uint8_t rw[crypto_kdf_hkdf_sha512_KEYBYTES]) {
  public_key oprf_out;
  // Calculate oprf using hashed pw
  unsigned char hashed_pw[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(hashed_pw, (const unsigned char *) pw, pw_len);

#ifdef DEBUG
  // Send hashed pw to server to check oprf calculation
  send(sock, hashed_pw, sizeof(hashed_pw), 0);
#endif
  
  // Perform actual OPRF calculation between client and server
#ifndef NR_OPRF
  if(opus_c(sock, hashed_pw, sizeof(hashed_pw), &oprf_out) != 0) return -1;
#else
  if(nr_oprf_c(sock, hashed_pw, sizeof(hashed_pw), &oprf_out) != 0) return -1;
#endif
  
#ifdef DEBUG
  printf("out:\n");
  uint_print(&oprf_out.A);
#endif

  // Calculate randomized password (rw) from password and output of OPRF
  oprf_finalize(pw, pw_len, &oprf_out, rw);
  return 0;
}

int oprf_s(int sock, const private_key *oprf_keys, const unsigned char *seed) {
#ifdef DEBUG
  // Let server verify OPRF result
  unsigned char hashed_pw[crypto_hash_sha256_BYTES];
  if(read_len(sock, hashed_pw, sizeof(hashed_pw), "hashed pw len") == -1) return -1;
  printf("correct out:\n");
#ifndef NR_OPRF
  check_oprf(hashed_pw, sizeof(hashed_pw), oprf_keys);
#else
  public_key out;
  kat(seed, hashed_pw, &out);
  uint_print(&out.A);
#endif
#endif
  
  // Perform actual OPRF calculation between client and server
#ifndef NR_OPRF
  (void) seed;
  if(opus_s(sock, oprf_keys, crypto_hash_sha256_BYTES) != 0) return -1;
#else
  (void) oprf_keys;
  if(nr_oprf_s(sock, seed, crypto_hash_sha256_BYTES) != 0) return -1;
#endif

  return 0;
}

/// Adapted oprf_finalize from libopaque/src/opaque.c 
void oprf_finalize(const char *pw, const uint16_t pw_len, const public_key *oprf_out,
  uint8_t *rw) {
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);

  uint16_t size = htons(pw_len);
  crypto_hash_sha512_update(&state, (uint8_t *) &size, 2);
  crypto_hash_sha512_update(&state, (const unsigned char *) pw, pw_len);

  size = htons(64);
  crypto_hash_sha512_update(&state, (uint8_t *) &size, 2);
  crypto_hash_sha512_update(&state, (uint8_t *) oprf_out->A.c, 64);

  const uint8_t dst[] = "Finalize";
  size = sizeof(dst) - 1;
  crypto_hash_sha512_update(&state, dst, size);

  uint8_t concated[2*crypto_hash_sha512_BYTES];
  uint8_t *y = concated;
  uint8_t *hardened = concated + crypto_hash_sha512_BYTES;
  crypto_hash_sha512_final(&state, y);

  uint8_t salt[crypto_pwhash_SALTBYTES] = {0};
  if(crypto_pwhash(hardened, crypto_hash_sha512_BYTES,
                  (const char *) y, crypto_hash_sha512_BYTES, salt,
                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_MEMLIMIT_INTERACTIVE,
                  crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("pwhash failed\n");
    exit(-1);
  }

  crypto_kdf_hkdf_sha512_extract(rw, NULL, 0, concated, 2*crypto_hash_sha512_BYTES);
}

#ifdef TLS_OPAQUE
int SSL_read_all(SSL *ssl, void *buf, int num) {
  int length = 0, ret = 0;
  while(length != num) {
    if((ret = SSL_read(ssl, (void *) (((uintptr_t) buf) + length), num - length)) <= 0) break;
    length += ret;
  }

  return (length == num) ? 0 : -1;
}
#endif
