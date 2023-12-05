#include <iostream>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <atomic>
#include <mutex>
#include <thread>
#include <opus-psi/SecureRandom.h>
#include <opus-psi/utils/Log.h>
#include <opus-psi/ChannelWrapper.h>
#include <opus-psi/BitVector.h>
#include <opus-psi/cuckoofilter/cuckoofilter.h>
#include <opus-psi/csidh-20210627/csidh.h>
#include <opus-psi/csidh-20210627/utils.h>
#include <opus-psi/utils/Log.h>

using namespace OpusPsi;

size_t nr_items=0;
const size_t hashlen=128;
typedef cuckoofilter::CuckooFilter<uint64_t *, 32, cuckoofilter::SingleTable, cuckoofilter::TwoIndependentMultiplyShift256> CuckooFilter;
CuckooFilter *cf_;
CSocketChannel *ChanSend;
CSocketChannel *ChanRecv;
std::atomic<bool> DONE=ATOMIC_VAR_INIT(false);


void setup(){
  // very similar to droidcrypto
  std::chrono::high_resolution_clock::time_point time_start, time_end;
  time_start = std::chrono::high_resolution_clock::now();
  uint64_t num_server_elements;
  uint64_t cfsize;
  auto time1 = std::chrono::high_resolution_clock::now();
  ChanRecv->recv((uint8_t *)&num_server_elements, sizeof(num_server_elements));
  num_server_elements = be64toh(num_server_elements);

  uint64_t size_in_tags, step;
  ChanRecv->recv((uint8_t *)&size_in_tags, sizeof(size_in_tags));
  ChanRecv->recv((uint8_t *)&step, sizeof(step));
  size_in_tags = be64toh(size_in_tags);
  step = be64toh(step);
  //auto time1 = std::chrono::high_resolution_clock::now();
  cf_ = new CuckooFilter(num_server_elements);
  std::chrono::duration<double> deser = std::chrono::duration<double>::zero();

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> tmp;
    ChanRecv->recv((uint8_t *)&cfsize, sizeof(cfsize));
    cfsize = be64toh(cfsize);
    tmp.resize(cfsize);
    ChanRecv->recv(tmp.data(), cfsize);
    auto time_der1 = std::chrono::high_resolution_clock::now();
    cf_->deserialize(tmp, i);
    auto time_der2 = std::chrono::high_resolution_clock::now();
    deser += (time_der2 - time_der1);
  }
  std::vector<unsigned __int128> params(5);
  for (auto &par : params) {
    ChanRecv->recv((uint8_t *)&par, sizeof(par));
  }
  cf_->SetTwoIndependentMultiplyShiftParams(params);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans = time3 - time_start;

  Log::v("Setup", "Time: %f s", trans.count());
}

std::deque<pk_res> client_res;
std::mutex m;
std::mutex b;
std::condition_variable full;
std::condition_variable almost_empty;
std::vector<large_private_key> blinder; 
std::mutex done_mx;
std::chrono::time_point<std::chrono::system_clock> time4;


void receive(size_t remaining){
  remaining=remaining*(hashlen+1);
  while(DONE!=true){
    pk_res res; 
    ChanRecv->recv((uint8_t*)&res, sizeof(pk_res));
    std::unique_lock<std::mutex> lm(m);
    client_res.push_back(res);
    lm.unlock();
    full.notify_one();
    remaining--;
    if(DONE == true)
      return;

    if(client_res.size()<3){
      almost_empty.notify_one();
    }
  }
}

void initialize(size_t elms){
  // will be first to touch anyways
  std::unique_lock<std::mutex> lb(b);
  blinder.reserve(elms);
  lb.unlock();

  size_t current=0; 
  while(current < elms){
    // queue is not that full, add more elements  
    public_key curve={0};
    pk_req r_E;
    r_E.id=current; 
    r_E.seq=0; 
    private_key eph_blinder={0}; 
    csidh_private(&eph_blinder);
    csidh(&r_E.E, &base, &eph_blinder);
    for(size_t i=0; i<NUM_PRIMES; ++i){
      blinder[current].e[i]=0;
    }
    std::unique_lock<std::mutex> lc(b);
    sub_large_key(&blinder[current], eph_blinder);
    lc.unlock();
    ChanSend->send((uint8_t *)&r_E,sizeof(pk_req));
    ++current;
  }
  return;
}



void evaluate(std::vector<block> elements){
  size_t done=elements.size(); 
  // start by sending all initial elements, not ideal
  while(done>0){
    std::unique_lock<std::mutex> lm(m);
    full.wait(lm, []{return !client_res.empty();});
    pk_res res=client_res.front();
    client_res.pop_front();
    lm.unlock();

    private_key eph_blinder={0}; 
    csidh_private(&eph_blinder);
    public_key curve;
    if(res.seq<hashlen){
      BitVector bv; 
      bv.assign(elements[res.id]);

      if(bv[res.seq]){
        memcpy(&curve, &res.E1, sizeof(public_key));
      }
      else{
        memcpy(&curve, &res.E0, sizeof(public_key));
      }
      pk_req r_E;
      std::unique_lock<std::mutex> lc(b);
      sub_large_key(&blinder[res.id], eph_blinder);
      lc.unlock();
      r_E.id=res.id; 
      r_E.seq=(res.seq+1); 
      csidh(&r_E.E, &curve, &eph_blinder);
      ChanSend->send((uint8_t *)&r_E,sizeof(pk_req));
    }
    else if(res.seq==hashlen){
      large_csidh(&curve, &res.E0, &blinder[res.id]);
      if (cf_->Contain(curve.A.c) == cuckoofilter::Ok) {
#ifdef DEBUG
        Log::v("PSI", "Intersection C%d", res.id);
#endif
      }
      --done;
      if(done==0){
        auto time6 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> recv = time6 - time4;
        Log::v("Online", "Time: %f s", recv.count());
        Log::v("Online", "Sent: %f kiB", (float)(ChanSend->getBytesSent())/1024.0);
        Log::v("Online", "Recv: %f kiB", (float)(ChanRecv->getBytesRecv())/1024.0);
        exit(0);
      }
    }
  }
}

void online(std::vector<block> elements){
  time4 = std::chrono::high_resolution_clock::now();

  size_t num_client_elements = htobe64(elements.size());
  ChanSend->send((uint8_t *)&num_client_elements, sizeof(num_client_elements));

  std::thread init(initialize, elements.size());
  std::thread rec(receive, elements.size());
  std::thread eval(evaluate, elements);
  init.join();
  rec.join();
  eval.join();

}


int main(int argc, char** argv) {

  if(argc != 4) {
    std::cout << "usage: " << argv[0] << " {ip} {port} {log2(num_inputs)}" << std::endl;
    return -1;
  }
  int port = std::stoi(std::string(argv[2]));
  if(1024 > port || port > 65534) {
    std::cout << "port should be between 1024 and 65534" << std::endl;
    return -1;
  }
  int exp = std::stoi(std::string(argv[3]));
  if(0 > exp || exp > 32) {
    std::cout << "log2(num_inputs) should be between 0 and 32" << std::endl;
    return -1;
  }
  size_t num_inputs = 1ULL << exp;
  //client

  SecureRandom rnd;
  std::vector<block> elements; 
  // get one good result to test intersection
  for(size_t i = 1; i < num_inputs; i++) {
    elements.push_back(rnd.randBlock());
  }
  elements.push_back(toBlock((const uint8_t*)"ffffffff88888888"));
  ChanRecv=new CSocketChannel (argv[1], port, false);
  ChanSend=new CSocketChannel (argv[1], port+1, false);

  setup(); 
  online(elements); 
  return 0;
}


