#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <gmpxx.h>
#include <cinttypes>
#include "pq-ot/pq-ot.h"
#include "emp-tool/utils/block.h"
#include "emp-tool/utils/prg.h"
#include "cuckoofilter/cuckoofilter.h"


extern "C"{
#include "../CSI-FiSh/fp.h"
#include "../CSI-FiSh/csidh.h"
#include "../CSI-FiSh/classgroup.h"
#include <openssl/rand.h>
#include <unistd.h>
#include <time.h>
}

using namespace emp;
const size_t N=128; 
bool input[N];
//#define DEBUG

// for offline computation / KAT verification
private_key priv_key[N+1];
mpz_t mpz_keys[N+1];

void prf(block element, public_key *pk){
  mpz_t t; 
  mpz_init(t);
  mpz_add(t,t,mpz_keys[0]);
  uint64_t x = static_cast<uint64_t>(_mm_extract_epi64(element, 0));
  for(size_t i=0; i<64; ++i){
    if(x&(1<<i))
      mpz_add(t,t,mpz_keys[i+1]);
  }
  x = static_cast<uint64_t>(_mm_extract_epi64(element, 1));
  for(size_t i=0; i<64; ++i){
    if(x&(1<<i))
      mpz_add(t,t,mpz_keys[i+65]);
  }
  private_key priv;
  mpz_fdiv_r(t,t,cn);
  mpz_add(t,t,cn);
  mod_cn_2_vec(t,priv.e);
  action(pk, &base, &priv);
  mpz_clear(t);
#ifdef DEBUG
  for(size_t i=0; i<8; ++i)
    printf("%" PRIu64 " ",pk->A.c[i]);
  puts("");
#endif
}

void online(NetIO *io){
#ifdef DEBUG
  auto begin = io->send_counter;
  auto time2 = std::chrono::high_resolution_clock::now();
#endif
  PQOT ot(io, 1, 1, 17);
  io->sync();
  ot.keygen();
#ifdef DEBUG
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv = time3- time2;
  auto end = io->send_counter-begin;
  printf("CSI-FiSh-OPRF-Server: keygen Time: %f s\n\t Keygen Comm. : %f kiB\n ", recv.count(), (end /1024.0));
#endif
  auto begin_o = io->send_counter;
  auto begin_r = io->recv_counter;

  size_t num_client_elements, num_elements;
  io->recv_data((uint8_t *)&num_client_elements, sizeof(num_client_elements));
  num_elements = be64toh(num_client_elements);

  auto time4 = std::chrono::high_resolution_clock::now();

  for(size_t runs=0; runs<num_elements; ++runs){
    /*
     * generate blinding keys
     */
    mpz_t blinder;
    mpz_init(blinder);

    unsigned char ephem_seed[SEED_BYTES*N]; 
    RAND_bytes(ephem_seed,SEED_BYTES*N);
    mpz_t *m_0;
    mpz_t *m_1;
    m_0 = new mpz_t[N];
    m_1 = new mpz_t[N];

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
    io->sync();
    ot.send_ot(m_0, m_1, N, sizeof(private_key)*8);
#ifdef DEBUG
    puts("Sent OT");
#endif

    private_key priv={0}; 
    mpz_add(blinder,blinder,mpz_keys[0]);
    public_key result;
    mod_cn_2_vec(blinder, priv.e); 
    action(&result, &base, &priv);
    io->send_data(&result, sizeof(public_key)); 
#ifdef DEBUG
    puts("sent unblinder");
#endif
    for(size_t i=0; i<N; ++i){
      mpz_clears(m_0[i],m_1[i], NULL);
    }
  }

  auto time5 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv_t = time5- time4;

  printf("[Online] Time: %f s\n", recv_t.count());
  printf("[Online] Sent: %f kiB\n", (float)(io->send_counter-begin_o)/1024.0);
  printf("[Online] Recv: %f kiB\n", (float)(io->recv_counter-begin_r)/1024.0);


  delete io;
}

void setup(NetIO *io,std::vector<block> &elements){

  auto time0 = std::chrono::high_resolution_clock::now();
  init_classgroup();
  /*
   * generate long-term server keys
   */

  unsigned char seed[SEED_BYTES*(N+1)]; 
  // buffer, number
  RAND_bytes(seed,SEED_BYTES*(N+1));
  for(size_t i=0; i<N+1; ++i){
    mpz_init(mpz_keys[i]); 
    sample_mod_cn_with_seed(seed+(i*SEED_BYTES),mpz_keys[i]); 
    mod_cn_2_vec(mpz_keys[i], priv_key[i].e); 
  }
  size_t num_elements=elements.size();

  public_key *prf_out=(public_key*)calloc(sizeof(public_key), elements.size());

  for (size_t i = 0; i < elements.size(); ++i) {
    prf(elements[i], &prf_out[i]);
  }
  elements.clear();

#ifdef DEBUG
  puts("build filter");
#endif

  typedef cuckoofilter::CuckooFilter<
    uint64_t *, 32, cuckoofilter::SingleTable,
             cuckoofilter::TwoIndependentMultiplyShift256>
               CuckooFilter;
  CuckooFilter cf(num_elements);

  for (size_t i = 0; i < num_elements; i++) {
    auto success = cf.Add(prf_out[i].A.c);
    (void)success;
    assert(success == cuckoofilter::Ok);
  }
#ifdef DEBUG
  printf("PSI: Built CF");
  printf("CF: %s", cf.Info().c_str());
#endif
  auto num_server_elements = htobe64(num_elements);
  auto begin_o=io->send_counter;
  io->sync();
  io->send_data((uint8_t *)&num_server_elements, sizeof(num_server_elements));

  // send cuckoofilter in steps to save memory
  const uint64_t size_in_tags = cf.SizeInTags();
  const uint64_t step = (1 << 16);
  uint64_t uint64_send;
  uint64_send = htobe64(size_in_tags);
  io->send_data((uint8_t *)&uint64_send, sizeof(uint64_send));
  uint64_send = htobe64(step);
  io->send_data((uint8_t *)&uint64_send, sizeof(uint64_send));

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> cf_ser = cf.serialize(step, i);
    uint64_t cfsize = cf_ser.size();
    uint64_send = htobe64(cfsize);
    io->send_data((uint8_t *)&uint64_send, sizeof(uint64_send));
    io->send_data(cf_ser.data(), cfsize);
  }

  std::vector<unsigned __int128> hash_params =
    cf.GetTwoIndependentMultiplyShiftParams();
  for (auto &par : hash_params) {
    io->send_data((uint8_t *)&par, sizeof(par));
  }

  auto time4 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans_time = time4 - time0;

  printf("[Setup] Time: %f s\n", trans_time.count());
  printf("[Setup] Sent: %f kiB\n", io->send_counter-begin_o / 1024.0);

  free(prf_out); 
  prf_out=NULL; 

}

int main(int argc, char* argv[])
{
  if(argc != 3){
    perror("usage: {port} {log2(num_inputs)}");
    exit(1);
  }

  size_t port=atoll(argv[1]);
  if(port==0){
    perror("Port needs to be a nonzero integer. ");
    exit(1);
  }
  else if(port>=(1<<16)){
    perror("Port needs to be an integer in the range 1--(1<<16-1)");
    exit(1);
  }

  size_t exp = atoll(argv[2]);
  if(0 > exp || exp > 32) {
    perror("log2(num_inputs) should be between 0 and 32");
    exit(1);
  }

  NetIO* io = new NetIO(NULL, port);
  PRG prg;
  size_t num_inputs = 1ULL << exp;
  std::vector<block> elements;
  // get one good result to test intersection
  elements.push_back(makeBlock(0xffffffff, 0x88888888));
  for(size_t i = 1; i < num_inputs; i++) {
    block b;
    prg.random_block(&b);
    elements.push_back(b);
  }
  setup(io, elements);
  online(io);
}


