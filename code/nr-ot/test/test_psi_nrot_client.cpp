#include <cstdlib>
#include <cstdio>
#include <cinttypes>
#include <string.h>
#include <unistd.h>
#include <gmpxx.h>
#include <cuckoofilter/cuckoofilter.h>

#include "pq-ot/pq-ot.h"
#include "emp-tool/utils/block.h"
#include "emp-tool/utils/prg.h"

extern "C"{
#include "fp.h"
#include "csidh.h"
#include "classgroup.h"
}


typedef cuckoofilter::CuckooFilter<uint64_t *, 32, cuckoofilter::SingleTable, cuckoofilter::TwoIndependentMultiplyShift256> CuckooFilter;
CuckooFilter *cf_;
//#define DEBUG

using namespace emp;
const size_t N=128;

void setup(NetIO* io) {
  std::chrono::high_resolution_clock::time_point time_start, time_end;
  time_start = std::chrono::high_resolution_clock::now();
  auto begin=io->send_counter;
  /*
   * receive and parse Cuckoo filter
   */
  uint64_t num_server_elements;
  uint64_t cfsize;
  io->sync();
  io->recv_data((uint8_t *)&num_server_elements, sizeof(num_server_elements));
  num_server_elements = be64toh(num_server_elements);

  uint64_t size_in_tags, step;
  io->recv_data((uint8_t *)&size_in_tags, sizeof(size_in_tags));
  io->recv_data((uint8_t *)&step, sizeof(step));
  size_in_tags = be64toh(size_in_tags);
  step = be64toh(step);
  //auto time1 = std::chrono::high_resolution_clock::now();
  cf_ = new CuckooFilter(num_server_elements);
  std::chrono::duration<double> deser = std::chrono::duration<double>::zero();

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> tmp;
    io->recv_data((uint8_t *)&cfsize, sizeof(cfsize));
    cfsize = be64toh(cfsize);
    tmp.resize(cfsize);
    io->recv_data(tmp.data(), cfsize);
    auto time_der1 = std::chrono::high_resolution_clock::now();
    cf_->deserialize(tmp, i);
    auto time_der2 = std::chrono::high_resolution_clock::now();
    deser += (time_der2 - time_der1);
  }
  std::vector<unsigned __int128> params(5);
  for (auto &par : params) {
    io->recv_data((uint8_t *)&par, sizeof(par));
  }
  cf_->SetTwoIndependentMultiplyShiftParams(params);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans = time3 - time_start;
  auto end=io->send_counter-begin;

  printf("[Setup] Time: %f s\n", trans.count());
}


void online(std::vector<block> elements, NetIO *io){
#ifdef DEBUG
  auto begin_ot = io->send_counter;
  auto time1 = std::chrono::high_resolution_clock::now();
#endif
  PQOT ot(io, 2, 1, 17);
  io->sync();
  //puts("CSI-FiSh-OPRF-Client: Connected to server");
  ot.keygen(); 
#ifdef DEBUG
  auto time2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv = time2 - time1;
  printf("CSI-FiSh-OPRF-Client: Keygen Time: %f s\n\tKeygen comms: %f kiB\n ", recv.count(),
      io->send_counter-begin_ot /  1024.0);
#endif

  auto begin = io->send_counter;
  auto begin_r = io->recv_counter;

  size_t num_client_elements = htobe64(elements.size());
  io->send_data((uint8_t *)&num_client_elements, sizeof(num_client_elements));


  public_key *prf_out=(public_key*)calloc(sizeof(public_key), elements.size());
  auto time4 = std::chrono::high_resolution_clock::now();
  for (auto runs = 0;runs < elements.size(); runs++) {
    mpz_t *m_0;
    m_0=new mpz_t[N];
    bool input[N]={0};

    /*
     * fill OPRF with some value
     * to test correctness, server and client need the same one (e.g. true for
     * all)
     */
    uint64_t x = static_cast<uint64_t>(_mm_extract_epi64(elements[runs], 0));
    for(size_t i=0; i<64; ++i){
      input[i]=x&(1<<i);
      mpz_init(m_0[i]);
    }
    x = static_cast<uint64_t>(_mm_extract_epi64(elements[runs], 1));
    for(size_t i=0; i<64; ++i){
      input[i+64]=x&(1<<i);
      mpz_init(m_0[i+64]);
    }

#ifdef DEBUG
    puts("Receiving...");
#endif
    io->sync();
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
    action(&prf_out[runs], &result, &priv);
#ifdef DEBUG
    puts("Client OPRF result");
    for(size_t i=0; i<8; ++i)
      printf("%" PRIu64 " ", result.A.c[i]);
    puts("");
#endif

  }

  /*
   * do intersection
   */
  std::vector<size_t> res;
  for (size_t i = 0; i < elements.size(); i++) {
    if (cf_->Contain(prf_out[i].A.c) == cuckoofilter::Ok) {
#ifdef DEBUG
      printf("PSI: Intersection C%d\n", i);
#endif
      res.push_back(i);
    }
  }

  auto time6 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> recv2 = time6 - time4;
  printf("[Online] Time: %f s\n", recv2.count());
  printf("[Online] Sent: %f kiB\n", (float)(io->send_counter-begin)/1024.0);
  printf("[Online] Recv: %f kiB\n", (float)(io->recv_counter-begin_r)/1024.0);

  delete io; 
}



int main(int argc, char *argv[])
{
  if(argc != 4){
    perror("usage: {ip} {port} {log2(num_inputs)}");
    exit(1);
  }

  char* hostname=argv[1];
  size_t port=atoll(argv[2]);

  if(port==0){
    perror("invalid port");
    exit(1);
  }


  int exp = std::stoi(std::string(argv[3]));
  if(0 > exp || exp > 32) {
    perror("log2(num_inputs) should be between 0 and 32");
    exit(1);
  }
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


  NetIO* io = new NetIO(hostname, port);

  const size_t N=128; 
  init_classgroup();
  unsigned char seed[SEED_BYTES*(N+1)]; 
  RAND_bytes(seed,SEED_BYTES*(N+1));

  setup(io);
  online(elements,io);

  clear_classgroup();

  return 0; 
}

