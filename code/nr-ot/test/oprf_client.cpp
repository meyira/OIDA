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

//#define DEBUG

using namespace emp;

const size_t ITERATIONS=10; 

int main(int argc, char *argv[])
{
  if(argc != 3){
    perror("usage: IP, port");
    exit(1);
  }

  const size_t N=128; 

  char* hostname=argv[1];
  size_t port=atoll(argv[2]);

  if(port==0){
    perror("invalid port");
    clear_classgroup();
    exit(1);
  }

  NetIO* io = new NetIO(hostname, port);
  // netio, role, thread, fhe bitlen
  PQOT ot(io, 2, 1, 17);
  io->sync();
#ifdef DEBUG
  puts("CSI-FiSh-OPRF-Client: Connected to server");
  auto begin = io->send_counter;
  auto time1 = std::chrono::high_resolution_clock::now();
#endif
  ot.keygen(); 
#ifdef DEBUG
  auto time2 = std::chrono::high_resolution_clock::now();
  auto end = io->send_counter-begin;
  std::chrono::duration<double> recv = time2 - time1;
  printf("CSI-FiSh-OPRF-Client: Keygen Time: %f s\n\tKeygen comms: %f kiB\n ", recv.count(),
      end /  1024.0);

  recv.zero();
#endif
  {  
    FILE *f = fopen("client.csv", "a");
    if(f==NULL) {
      perror("Error opening file.");
      exit(1);
    }
    fprintf(f, "seconds kibibytes \n");
  }

  init_classgroup();
  unsigned char seed[SEED_BYTES*(N+1)]; 
  RAND_bytes(seed,SEED_BYTES*(N+1));

  for(size_t runs=0; runs<ITERATIONS; ++runs){
    auto begin_e = io->send_counter;
    /*
     * OPRF
     */
    auto time3 = std::chrono::high_resolution_clock::now();
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
    auto time4 = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double>  recv_e =time4 - time3;

    auto end_e = io->send_counter-begin_e;
    FILE *f = fopen("client.csv", "a");
    if(f==NULL) {
      perror("Error opening file.");
      exit(1);
    }
    fprintf(f, "%f %f \n", recv_e.count(), (end_e /  1024.0));
  }


  // free(t); 
  // free(m_0);
  delete io; 
  return 0; 
}

