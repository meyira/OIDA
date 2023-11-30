#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <functional>
#include <condition_variable>
#include <mutex>
#include <map>
#include <semaphore.h>
#include <opus-psi/SecureRandom.h>
#include <opus-psi/utils/Log.h>
#include <opus-psi/cuckoofilter/cuckoofilter.h>
#include <opus-psi/ChannelWrapper.h>
#include <opus-psi/BitVector.h>
#include <opus-psi/csidh-20210627/csidh.h>
#include <opus-psi/csidh-20210627/utils.h>
#include <random>

const size_t hashlen=128;
const size_t keylen=129;
size_t num_server_elements;
using namespace OpusPsi;

CSocketChannel *ChanSend;
CSocketChannel *ChanRecv;
std::array<private_key, keylen> private_keys;
std::deque<pk_req> client_req; 
std::mutex m;
std::condition_variable full;


std::vector<public_key> prf(std::vector<block> elements){
  std::vector<public_key> prfOut;
  prfOut.reserve(elements.size());
  large_private_key aggregated;
  for (size_t i = 0; i < elements.size(); ++i) {
    BitVector bv;
    bv.assign(elements[i]);
    for(size_t k=0; k<NUM_PRIMES; ++k)
      aggregated.e[k]=private_keys[0].e[k];
    for (size_t j = 0; j < hashlen; ++j) {
      if(bv[j]){
        add_large_key(&aggregated, private_keys[j+1]);
      }
    }
    large_csidh(&prfOut[i], &base, &aggregated);
  }
  Log::v("PSI", "PRF done");
  return prfOut;
}

void setup(std::vector<block> elements){

  auto time0 = std::chrono::high_resolution_clock::now();
  typedef cuckoofilter::CuckooFilter<
    uint64_t *, 32, cuckoofilter::SingleTable,
             cuckoofilter::TwoIndependentMultiplyShift256>
               CuckooFilter;
  std::vector<public_key> prfOut= prf(elements);
  // clear elements to make space in memory
  elements.clear();
  CuckooFilter cf(num_server_elements);

  /*
   * fill Cuckoo filter
   */

  //auto time1 = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < num_server_elements; i++) {
    auto success = cf.Add(prfOut[i].A.c);
    (void)success;
    assert(success == cuckoofilter::Ok);
  }
  Log::v("PSI", "Built CF");
  Log::v("CF", "%s", cf.Info().c_str());
  num_server_elements = htobe64(num_server_elements);
  ChanSend->send((uint8_t *)&num_server_elements, sizeof(num_server_elements));

  // send cuckoofilter in steps to save memory
  const uint64_t size_in_tags = cf.SizeInTags();
  const uint64_t step = (1 << 16);
  uint64_t uint64_send;
  uint64_send = htobe64(size_in_tags);
  ChanSend->send((uint8_t *)&uint64_send, sizeof(uint64_send));
  uint64_send = htobe64(step);
  ChanSend->send((uint8_t *)&uint64_send, sizeof(uint64_send));

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> cf_ser = cf.serialize(step, i);
    uint64_t cfsize = cf_ser.size();
    uint64_send = htobe64(cfsize);
    ChanSend->send((uint8_t *)&uint64_send, sizeof(uint64_send));
    ChanSend->send(cf_ser.data(), cfsize);

  }

  std::vector<unsigned __int128> hash_params =
    cf.GetTwoIndependentMultiplyShiftParams();
  for (auto &par : hash_params) {
    ChanSend->send((uint8_t *)&par, sizeof(par));
  }

  auto time4 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans_time = time4 - time0;
  Log::v("PSI",
      "Setup Time:\n\t%fs"
      "Trans,\n\t Setup Comm: %fMiB sent\n",
      trans_time.count(), ChanSend->getBytesSent() / 1024.0 / 1024.0);
}

void receive(size_t all){
  size_t remaining=all*(hashlen+1);
  size_t highest=0;
  while(remaining>=0){
    pk_req req; 
    ChanRecv->recv((uint8_t*)&req, sizeof(pk_req));
    // TODO magic sorting here, maybe with some fuzzing
    if(highest < req.seq){
      highest=req.seq-2;
      std::unique_lock<std::mutex> lk(m);
      client_req.push_front(req);
      lk.unlock();
    }
    else{
      std::unique_lock<std::mutex> lk(m);
      client_req.push_back(req);
      lk.unlock();
    }
    full.notify_one();
    remaining--;
  }
}

typedef struct BlindingMaterial{
  std::vector<private_key> ri;
  large_private_key unblinder;
};

void evaluate(size_t num_client_elements_){
  std::map<uint32_t, BlindingMaterial> rs;
  size_t finished=num_client_elements_*(hashlen+1);
  while(finished>=0){ 
    if(!(client_req.empty())){
      std::unique_lock<std::mutex> lk(m);
      full.wait(lk, []{return !client_req.empty();});
      pk_req req=client_req.front();
      client_req.pop_front();
      lk.unlock();
      pk_res s_E;
      if(req.seq<hashlen){
        if(!rs.contains(req.id)){
          // check if key exists
          BlindingMaterial B;
          std::memset(&B.unblinder, '\0',sizeof(B.unblinder));
          add_large_key(&B.unblinder, private_keys[0]);
          for(size_t i=0;i<hashlen; ++i){
            private_key k={0};
            csidh_private(&k);
            //std::unique_lock<std::mutex> ls(m);
            sub_large_key(&B.unblinder, k);
            B.ri.push_back(k);
            //ls.unlock();
          }
          // lock rs
          std::unique_lock<std::mutex> lkm(m);
          // full.wait(lkm, []{return !client_req.empty();});
          auto success=rs.insert(std::make_pair(req.id,B));
          lkm.unlock();
          if(!success.second){
            printf("Generating key material for %d at %d not possible: Insertion error.\n", req.id, req.seq);
            continue;
          }
        }

        s_E.id=req.id;
        s_E.seq=req.seq;
        // add next blinder, commutativity doesn't care which one tbh
        //csidh(&s_E.E0, &client_req[0].E, &rs[req.id][req.seq]);

        if(rs[req.id].ri.size()>0){
          std::unique_lock<std::mutex> lka(m);
          private_key single_use_blinder=rs[req.id].ri[0];
          rs[req.id].ri.erase(rs[req.id].ri.begin());
          lka.unlock();
          csidh(&s_E.E0, &req.E, &single_use_blinder);
          // add requested key
          csidh(&s_E.E1, &s_E.E0, &private_keys[req.seq+1]);
          ChanSend->send((uint8_t*)&s_E,sizeof(pk_res));
        }
        else{
          printf("Evaluation of element %d at %d not possible: Insufficient Blinding Material. Dropping request...\n", req.id, req.seq);
        }
      }
      else if(req.seq==hashlen){
        s_E.id=req.id;
        s_E.seq=req.seq;
        if(rs[req.id].ri.size()!=0){
          printf("Finalization of element %d not possible: Blinding Material Error. Dropping request...\n", req.id);
          continue;
        }
        large_csidh(&s_E.E0, &req.E, &rs[req.id].unblinder);
        ChanSend->send((uint8_t*)&s_E,sizeof(s_E));
        finished--;
        rs.erase(req.id);
      }
    }

  }

}

void online(){
  auto time3 = std::chrono::high_resolution_clock::now();
  // sendChan.clearStats();
  // recvChan.clearStats();
  size_t num_client_elements;

  ChanRecv->recv((uint8_t *)&num_client_elements, sizeof(num_client_elements));
  size_t num_client_elements_ = be64toh(num_client_elements);

  std::thread recv(receive, num_client_elements_);
  std::thread eval(evaluate, num_client_elements_);
  recv.join();
  eval.join();
  // done
  auto time4 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans_time = time4 - time3;
  Log::v("PSI",
      "Online Time:\n\t%fsec\n"
      "Online Comm: %fMiB recv\n",
      "Online Comm: %fMiB sent\n",
      trans_time.count(), ChanSend->getBytesSent() / 1024.0 / 1024.0,ChanRecv->getBytesSent() / 1024.0 / 1024.0);


}


int main(int argc, char** argv) {

  if(argc != 4) {
    std::cout << "usage: " << argv[0] << " {ip} {port} {log2(num_inputs)}" << std::endl;
    return -1;
  }
  int port = std::stoi(std::string(argv[2]));
  if(1023 > port || port > 65534) {
    std::cout << "port should be between 1024 and 65534, will be used for sending and receiving thread" << std::endl;
    return -1;
  }
  int exp = std::stoi(std::string(argv[3]));
  if(0 > exp || exp > 32) {
    std::cout << "log2(num_inputs) should be between 0 and 32" << std::endl;
    return -1;
  }
  num_server_elements = 1ULL << exp;
  //server

  /*
   * generate set inputs
   */
  SecureRandom rnd;
  std::vector<block> elements; 
  // get one good result to test intersection
  elements.push_back(toBlock((const uint8_t*)"ffffffff88888888"));
  for(size_t i=1; i<num_server_elements; ++i)
    elements.push_back(rnd.randBlock());

  for(size_t i=0; i<keylen; ++i){
    csidh_private(&private_keys[i]);
  }
  ChanSend=new CSocketChannel(argv[1], port, true);
  ChanRecv=new CSocketChannel(argv[1], port+1, true);

  setup(elements);
  online(); 
  return 0;
}


