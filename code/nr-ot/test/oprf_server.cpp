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

#define DEBUG
#define PRF
#define BENCH_KEYGEN
#define OPT_PRF


using namespace emp;
const size_t N=128; 
const size_t ITERATIONS=100; 
bool input[N];

// for offline computation / KAT verification
private_key priv_key[N+1];
mpz_t mpz_keys[N+1];

void kat(){
  public_key pk;
  mpz_t t; 
  mpz_init(t);
#ifdef OPT_PRF
  mpz_add(t,t,mpz_keys[0]);
#elif
  action(&pk,&base, &priv_key[0]);
#endif
  for(size_t i=0; i<N; ++i){
    // simulate random input
    if(i%2){
#ifdef OPT_PRF
  mpz_add(t,t,mpz_keys[i+1]);
#elif
  action(&pk,&pk, &priv_key[i+1]);
#endif
    }
  }
#ifdef OPT_PRF
  private_key priv;
  mpz_fdiv_r(t,t,cn);
  mpz_add(t,t,cn);
  mod_cn_2_vec(t,priv.e);
  action(&pk, &base, &priv);
  mpz_clear(t);
#endif 

#ifdef DEBUG
  for(size_t i=0; i<8; ++i)
    printf("%" PRIu64 " ",pk.A.c[i]);
  puts("");
#endif
}

void init(){
  //auto time0 = std::chrono::high_resolution_clock::now();
  init_classgroup();
  /*
   * generate long-term server keys
   */

  unsigned char seed[SEED_BYTES*(N+1)]; 
  // buffer, number
  RAND_bytes(seed,SEED_BYTES*(N+1));
  for(size_t i=0; i<N+1; ++i){
    mpz_init(mpz_keys[i]); 
  }
#ifdef BENCH_KEYGEN
  auto time0 = std::chrono::high_resolution_clock::now();
  for(size_t k=0; k<ITERATIONS; ++k){
#endif

    for(size_t i=0; i<N+1; ++i){
      sample_mod_cn_with_seed(seed+(i*SEED_BYTES),mpz_keys[i]); 
      mod_cn_2_vec(mpz_keys[i], priv_key[i].e); 
    }
#ifdef BENCH_KEYGEN
  }
  auto time1 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv = time1 - time0;
  printf("CSI-FiSh-OPRF-Server: Keygen Time: %f s\n", recv.count()/(double)ITERATIONS
      );
#endif

  /*
   * known answer test, uncomment to check correctness
   */ 
#ifdef PRF
  auto time2 = std::chrono::high_resolution_clock::now();
  for(size_t i=0; i<ITERATIONS; ++i){
    kat();
  }
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv2 = time3 - time2;
  printf("CSI-FiSh-OPRF-Server: PRF Time: %f s\n", recv2.count()/(double)ITERATIONS
      );
#endif
}

int main(int argc, char* argv[])
{
  if(argc != 2){
    puts("usage: port");
    return -1;
  }

  size_t port=atoll(argv[1]);
  if(port==0){
    puts("Port needs to be a nonzero integer. ");
    return -1;
  }
  else if(port>=(1<<16)){
    puts("Port needs to be an integer in the range 1--(1<<16-1)");
    return -1;
  }
  init();

  NetIO* io = new NetIO(NULL, port);
  PQOT ot(io, 1, 1, 17);

  // netio, role, thread, fhe bitlen
  io->sync();
  puts("CSI-FiSh-OPRF-Server: Connected to client");
  auto begin = io->send_counter;
  auto time2 = std::chrono::high_resolution_clock::now();
  ot.keygen();
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv = time3- time2;
  auto end = io->send_counter-begin;
  printf("CSI-FiSh-OPRF-Server: keygen Time: %f s\n\t Keygen Comm. : %f kiB\n ", recv.count(), (end /1024.0));
  begin = io->send_counter;

  auto time4 = std::chrono::high_resolution_clock::now();
  for(size_t runs=0; runs<ITERATIONS; ++runs){
    /*
     * generate blinding keys
     */
    mpz_t blinder;
    mpz_init(blinder);

    unsigned char ephem_seed[SEED_BYTES*N]; 
    RAND_bytes(ephem_seed,SEED_BYTES*N);
    mpz_t m_0[N];
    mpz_t m_1[N];
    for(size_t i=0; i<N; ++i){
      mpz_inits(m_0[i],m_1[i],NULL); 

      // sample blinder
      sample_mod_cn_with_seed(ephem_seed+(i*SEED_BYTES),m_0[i]); 

      // compute blinded key
      mpz_add(m_1[i],m_0[i],mpz_keys[i+1]);
      mpz_fdiv_r(m_1[i],m_1[i],cn); 
      mpz_add(m_1[i],m_1[i],cn); 
      mpz_sub(blinder,blinder,m_0[i]); 
    }

#ifdef DEBUG
    puts("Sending...");
#endif
    ot.send_ot(m_0, m_1, N, sizeof(private_key)*8);
#ifdef DEBUG
    puts("Sent OT");
#endif

    private_key priv={0}; 
    mpz_add(blinder,blinder,mpz_keys[0]);
    mpz_fdiv_r(blinder,blinder,cn); 
    mpz_add(blinder,blinder,cn); 
    mod_cn_2_vec(blinder, priv.e); 
    public_key result;
    action(&result, &base, &priv);
    io->send_data(&result, sizeof(public_key)); 
#ifdef DEBUG
    puts("sent unblinder");
#endif
  }

  auto time5 = std::chrono::high_resolution_clock::now();
  recv = time5- time4;
  end = io->send_counter;
  end= end- begin;
  printf("CSI-FiSh-OPRF-Server: average OPRF Time: %f s\n\t Average comm. : %f kiB\n ", recv.count()/(double)ITERATIONS, (end /  1024.0)/(double)ITERATIONS);

  delete io;
  return 0; 
}

