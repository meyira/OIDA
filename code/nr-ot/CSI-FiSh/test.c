#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "fp.h"
#include "csidh.h"
#include "classgroup.h"

int main()
{
  const size_t N=128; 
  init_classgroup();

  /*
   * generate long-term server keys
   */
  mpz_t mpz_keys[N+1];
  // for offline computation / KAT verification
  private_key priv_key[N+1];
  private_key priv_key_alt[N+1];

  unsigned char seed[SEED_BYTES*(N+1)]; 
  RAND_bytes(seed,SEED_BYTES*(N+1));
  for(size_t i=0; i<N+1; ++i){
    // TODO we can sample k_0  differently theoretically
    mpz_init(mpz_keys[i]); 
    sample_mod_cn_with_seed(seed+(i*SEED_BYTES),mpz_keys[i]); 
    mod_cn_2_vec(mpz_keys[i], priv_key[i].e); 
     mod_cn_2_vec(mpz_keys[i], priv_key_alt[i].e);
  }

  /*
   * generate long-term server keys
   */
  private_key blinder[N];
  private_key blinded_key[N];

  unsigned char ephem_seed[SEED_BYTES*N]; 
  RAND_bytes(ephem_seed,SEED_BYTES*N);
  for(size_t i=0; i<N; ++i){
    mpz_t a,b;
    mpz_inits(a,b,NULL); 

    // sample blinder
    sample_mod_cn_with_seed(ephem_seed+(i*SEED_BYTES),a); 
    mod_cn_2_vec(a, &blinder[i].e[0]); 

    // compute blinded key
    mpz_add(b,a,mpz_keys[i+1]);
    mpz_fdiv_r(b,b,cn); 
    mpz_add(b,b,cn); 
    mod_cn_2_vec(b, &blinded_key[i].e[0]); 

    // cleanup 
    mpz_clears(a,b,NULL); 
  }

  /*
   * KAT
   */
  bool input[N];
  public_key kat_result;
  large_private_key sum; 
  assign_large_key(&sum, &priv_key[0]);
  for(size_t i=0; i<N; ++i){
    input[i]=rand()%2;
    if(input[i])
      add_large_key(&sum, &priv_key[i+1]);
    // action(&kat_result, &kat_result, &priv_key[i+1]);
  }
  large_action(&kat_result, &base, &sum);

  public_key oprf_result;
  large_private_key priv={0}; 
  if(input[0]){
      add_large_key(&priv, &blinded_key[0]);
  }
  else{
    // rand
      add_large_key(&priv, &blinder[0]);
  }
  for(size_t i=1; i<N; ++i){
    if(input[i]){
      add_large_key(&priv, &blinded_key[i]);
    }
    else{
      // rand
      add_large_key(&priv, &blinder[i]);
    }
  }

  for(size_t i=0; i<N; ++i){
    sub_large_key(&priv, &blinder[i]);
  }
  add_large_key(&priv, &priv_key[0]);
  large_action(&oprf_result, &base, &priv);

  puts("KAT PRF result");
  fp_print(&kat_result.A);
  printf("\n");
  puts("OPRF result");
  fp_print(&oprf_result.A);
  printf("\n\n");
  if (memcmp(&oprf_result, &kat_result, sizeof(public_key)))
    printf("\x1b[31mNOT EQUAL!\x1b[0m\n");
  else
    printf("\x1b[32mequal.\x1b[0m\n");
  printf("\n");

cleanup2: 
  for(size_t i=0; i<N+1; ++i){
    mpz_clear(mpz_keys[i]); 
  }

cleanup1: 
  clear_classgroup();


  return 0; 
}

