#include <cstdlib>
#include <cstdio>
#include <cinttypes>
#include <string.h>
#include <unistd.h>
#include <gmpxx.h>
#include "pq-ot/pq-ot.h"

extern "C"{
#include "fp.h"
#include "csidh.h"
#include "classgroup.h"
}

#define DEBUG

using namespace emp;

const size_t ITERATIONS=100; 
int main(int argc, char *argv[])
{
  if(argc != 3){
    puts("usage: IP, port");
    return -1;
  }

  const size_t N=128; 
  init_classgroup();

  unsigned char seed[SEED_BYTES*(N+1)]; 
  RAND_bytes(seed,SEED_BYTES*(N+1));

  char* hostname=argv[1];
  size_t port=atoll(argv[2]);

  if(port==0){
    puts("invalid port");
    clear_classgroup();
    return -1;
  }

  NetIO* io = new NetIO(hostname, port);
  // netio, role, thread, fhe bitlen
  PQOT ot(io, 2, 1, 17);
  io->sync();
  puts("CSI-FiSh-OPRF-Client: Connected to server");
  auto begin = io->send_counter;
  auto time1 = std::chrono::high_resolution_clock::now();
  ot.keygen(); 
  auto time2 = std::chrono::high_resolution_clock::now();
  auto end = io->send_counter-begin;
  std::chrono::duration<double> recv = time2 - time1;
 printf("CSI-FiSh-OPRF-Client: Keygen Time: %f s\n\tKeygen comms: %f kiB\n ", recv.count(),
      end /  1024.0);

 recv.zero();
  for(size_t runs=0; runs<ITERATIONS; ++runs){
  /*
   * OPRF
   */
  time1 = std::chrono::high_resolution_clock::now();
  bool input[N];
  mpz_t m_0[N];

  /*
   * fill OPRF with some value
   * to test correctness, server and client need the same one (e.g. true for
   * all)
   */
  for(size_t i=0; i<N; ++i){
    input[i]=(i%2);
    mpz_init(m_0[i]);
  }

#ifdef DEBUG
  puts("Receiving...");
#endif
  ot.recv_ot(m_0, input, N, sizeof(private_key)*8);
#ifdef DEBUG
  puts("Received.");
#endif

  private_key priv={0};
  mpz_t t; 

  mpz_init(t);
  for(size_t i=0; i<N; ++i){
    mpz_add(t,t,m_0[i]);
    if(i%2){
      mpz_fdiv_r(t,t,cn);
      mpz_add(t,t,cn);
    }
  }
  mpz_fdiv_r(t,t,cn);
  mpz_add(t,t,cn);
  mod_cn_2_vec(t,priv.e);

  public_key result;
  io->recv_data(&result, sizeof(public_key));
  action(&result, &result, &priv);
#ifdef DEBUG
  puts("Client OPRF result");
  for(size_t i=0; i<8; ++i)
    printf("%" PRIu64 " ", result.A.c[i]);
  puts("");
#endif
  time2 = std::chrono::high_resolution_clock::now();

  recv =recv+ time2 - time1;
  }

  end = io->send_counter-begin;
  printf("CSI-FiSh-OPRF-Client: Overall Time: %f s\n\tSent: %f kiB\n ", recv.count()/(float)ITERATIONS,
      (end /  1024.0)/(double)ITERATIONS);


  // free(t); 
  // free(m_0);
  delete io; 
  return 0; 
}

