#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <gmpxx.h>
#include "pq-ot/pq-ot.h"
#include <cinttypes>

extern "C"{
#include "../CSI-FiSh/fp.h"
#include "../CSI-FiSh/csidh.h"
#include "../CSI-FiSh/classgroup.h"
#include <openssl/rand.h>
#include <unistd.h>
#include <time.h>
}

//#define DEBUG


using namespace emp;

void prf(private_key *priv_key, size_t N){
  public_key pk;
  large_private_key lpk={0};
  add_large_key(&lpk, &priv_key[0]);
  for(size_t i=0; i<N; ++i){
    // simulate random input
    if(rand()%2){
  add_large_key(&lpk, &priv_key[i+1]);
    }
  }
  large_action(&pk,&base,&lpk);
#ifdef DEBUG
  for(size_t i=0; i<8; ++i)
    printf("%" PRIu64 " ",pk.A.c[i]);
  puts("");
#endif
}
void prf_opt(mpz_t *mpz_keys, size_t N){
  public_key pk;
  mpz_t t; 
  mpz_init(t);
  mpz_add(t,t,mpz_keys[0]);
  for(size_t i=0; i<N; ++i){
    // simulate random input
    if(rand()%2){
      mpz_add(t,t,mpz_keys[i+1]);
    }
  }
  private_key priv;
  mpz_fdiv_r(t,t,cn);
  mpz_add(t,t,cn);
  mod_cn_2_vec(t,priv.e);
  action(&pk, &base, &priv);
  mpz_clear(t);

#ifdef DEBUG
  for(size_t i=0; i<8; ++i)
    printf("%" PRIu64 " ",pk.A.c[i]);
  puts("");
#endif
}

int main(int argc, char* argv[])
{

  remove("prf_csifish.csv");
  init_classgroup();

  FILE *noopt = fopen("prf_csifish.csv", "a");
  if(noopt==NULL) {
    perror("Error opening noopt file.");
    return -1;
  }
  fprintf(noopt, "It Bench1 Bench2\n");
  fclose(noopt);
  for(size_t k=0; k<512; k++){
    FILE *noopt = fopen("prf_csifish.csv", "a");
    if(noopt==NULL) {
      perror("Error opening noopt file.");
      return -1;
    }
    private_key priv_key[k+1];
    std::chrono::duration<double> prf_time , opt_time;
    prf_time=std::chrono::duration<double>::zero();
    opt_time=std::chrono::duration<double>::zero();
    for(size_t runs=0; runs<100; ++runs){
      unsigned char seed[SEED_BYTES*(k+1)];
      // buffer, number
      RAND_bytes(seed,SEED_BYTES*(k+1));
      mpz_t mpz_keys[k+1];

      for(size_t i=0; i<k+1; ++i){
        mpz_init(mpz_keys[i]);
        sample_mod_cn_with_seed(seed+(i*SEED_BYTES),mpz_keys[i]); 
        mod_cn_2_vec(mpz_keys[i], priv_key[i].e); 
      }
      auto time1 = std::chrono::high_resolution_clock::now();
      // for offline computation / KAT verification
      prf(priv_key, k);
      auto time2 = std::chrono::high_resolution_clock::now();
      prf_opt(mpz_keys, k);
      auto time3 = std::chrono::high_resolution_clock::now();
      prf_time += time2- time1;
      opt_time += time3- time2;
      for(size_t i=0; i<k+1; ++i){
        mpz_clear(mpz_keys[i]);
      }
    }
    fprintf(noopt, "%ld %f %f\n", k, prf_time.count()/100, opt_time.count()/100);
    fclose(noopt);
    prf_time=std::chrono::duration<double>::zero();
    opt_time=std::chrono::duration<double>::zero();

    printf("finished %ld\n", k);
  }

  return 0; 
}

