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
  /*
   * OT SETUP
   */
  std::chrono::high_resolution_clock::time_point time_start, time_end;
  time_start = std::chrono::high_resolution_clock::now();
  auto begin=io->send_counter;
  // time_end = std::chrono::high_resolution_clock::now();
  // std::chrono::milliseconds time_keygen = std::chrono::duration_cast<
  //   std::chrono::milliseconds>(time_end - time_start);

  // std::cout << "KeyGen Time: " << time_keygen.count() << " milliseconds" << std::endl;

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

  printf("Setup Client: Time: %fs\nSize: %fMiB\n", trans.count(), end/1024.0/1024.0 );
}


void online(std::vector<block> elements, NetIO *io){
  auto begin = io->send_counter;
  auto time1 = std::chrono::high_resolution_clock::now();
  PQOT ot(io, 2, 1, 17);
  io->sync();
  //puts("CSI-FiSh-OPRF-Client: Connected to server");
  ot.keygen(); 
  auto time2 = std::chrono::high_resolution_clock::now();
  auto end = io->send_counter-begin;
  std::chrono::duration<double> recv = time2 - time1;
  printf("CSI-FiSh-OPRF-Client: Keygen Time: %f s\n\tKeygen comms: %f kiB\n ", recv.count(),
      end /  1024.0);


  size_t num_client_elements = htobe64(elements.size());
  io->send_data((uint8_t *)&num_client_elements, sizeof(num_client_elements));


  public_key *prf_out=(public_key*)calloc(sizeof(public_key), elements.size());

  // // compute b_ij
  // block *choices = (block *)ot_choices_.data();
  // for (auto i = 0; i < elements.size(); i++) {
  //   choices[i] ^= elements[i];
  // }

  // // send correction bits
  // io->sync();
  // auto time4 = std::chrono::high_resolution_clock::now();
  // auto begin=io->send_counter;

  // io->send_data(ot_choices_.data(), elements.size() * 128 / 8);


  auto time4 = std::chrono::high_resolution_clock::now();
  for (auto runs = 0;runs < elements.size(); runs++) {
    //  BitVector bv;
    //  bv.assign(elements[i]);
    //  large_private_key aggregated={0};

    //  for(size_t j=0; j<HASHLEN; ++j){
    //    // receive end evaluate corrected key
    //    private_key recvd;
    //    io->recv_data(&recvd, sizeof(private_key));

    //    if(bv[j]){
    //      for(size_t k=0; k<NUM_PRIMES; ++k){
    //        recvd.e[k]^=ots_[i*HASHLEN+j].e[k];
    //      }
    //      add_large_key(&aggregated, recvd);
    //    }
    //    else{
    //      add_large_key(&aggregated, ots_[i*HASHLEN+j]);
    //    }
    //  }
    //  // receive and evaluate group element with inverted
    //  io->recv_data(&prf_out[i].A.c, sizeof(public_key));
    //  large_csidh(&prf_out[i], &prf_out[i], &aggregated);


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
      printf("PSI: Intersection C%d\n", i);
      res.push_back(i);
    }
  }

  auto time6 = std::chrono::high_resolution_clock::now();
  recv = time6 - time4;
  end=io->send_counter-begin;
  printf("NR-OT Online Time: %fs\n\tComms: %f MiB\n", recv.count(), end/1024.0/1024.0);

  delete io; 
}



int main(int argc, char *argv[])
{
  if(argc != 4){
    puts("usage: {ip} {port} {log2(num_inputs)}");
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


  int exp = std::stoi(std::string(argv[3]));
  if(0 > exp || exp > 32) {
    std::cout << "log2(num_inputs) should be between 0 and 32" << std::endl;
    return -1;
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
  setup(io);
  online(elements,io);

  return 0; 
}
