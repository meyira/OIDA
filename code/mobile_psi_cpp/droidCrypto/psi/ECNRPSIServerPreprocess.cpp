#include <assert.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/SHA1.h>
#include <droidCrypto/SHAKE128.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtSender.h>
#include <droidCrypto/ot/VerifiedSimplestOT.h>
#include <droidCrypto/psi/ECNRPSIServerPreprocess.h>
#include <droidCrypto/utils/Log.h>
#include <endian.h>
#include <thread>
#include <map>
#include <tuple>
#include "../cuckoofilter/cuckoofilter.h"

namespace droidCrypto {
    const size_t hashlen=128; 

  void findDuplicates(std::vector<std::array<uint8_t, 33>> &vecOfElements, std::map<std::array<uint8_t, 33>, int> & countMap)
  {
    // Iterate over the vector and store the frequency of each element in map
    for (auto & elem : vecOfElements)
    {
      auto result = countMap.insert(std::pair<std::array<uint8_t, 33>, int>(elem, 1));
      if (result.second == false)
        result.first->second++;
    }
    // Remove the elements from Map which has 1 frequency count
    for (auto it = countMap.begin() ; it != countMap.end() ;)
    {
      if (it->second == 1)
        it = countMap.erase(it);
      else
        it++;
    }
  }


  ECNRPSIServerPreprocess::ECNRPSIServerPreprocess(ChannelWrapper &chan, size_t num_threads /*=1*/)
    : PhasedPSIServer(chan, num_threads),
    prng_(PRNG::getTestPRNG()),
    prf_(prng_, hashlen),
    num_client_elements_(0) {}

  void ECNRPSIServerPreprocess::Setup(std::vector<block> &elements) {
    typedef cuckoofilter::CuckooFilter<
      uint64_t *, 32, cuckoofilter::SingleTable,
               cuckoofilter::TwoIndependentMultiplyShift256>
                 CuckooFilter;

    auto timex = std::chrono::high_resolution_clock::now();
    size_t num_server_elements = elements.size();
    std::vector<std::array<uint8_t, 33>> prfOut(num_server_elements);

    // MT-bounds
    size_t elements_per_thread = num_server_elements / num_threads_;

    /*
     * Preprocessed hashing here
     */
    auto keys=prf_.getKeys(); 

    /*
     * Parameters for LUT coordination: 
     * factor: length of a single block
     * entries: number of blocks
     * example with factor 4, hashlength 8, entries 2 
     * two blocks with four bits
     * 0000 0000
     */
    size_t factor=8; 
    size_t entries=hashlen/factor; 

    // preprocess keys
    REccNumber *lut=(REccNumber*)calloc(sizeof(REccNumber),entries*((1ULL<<factor)-1));   //start filling at 1 as 0 will have no effect; 
//     std::cout<<"LUT entry nr " <<entries*((1ULL<<factor)-1)<<std::endl; 
//     std::cout<<"nr keys " << keys.size()<<std::endl; 

    // for each blocks
    size_t key_idx=0;
    for(size_t i=0; i<entries; ++i){
      // for each possible combination
      size_t val=1;
      for(size_t j=0; j<((1ULL<<factor)-1); ++j){
        // add each key
        for(size_t k=0; k<factor; ++k){
          if(val & (1ULL<<k)){
            size_t idx=(((1ULL<<factor)-1)*i)+val-1; 
            if(lut[idx]==0)
              lut[idx]=keys[key_idx+k]; 
            else
              (lut[idx])*=keys[key_idx+k];
          }
        }
        ++val;
      }
      key_idx+=factor;
    }


    auto time0 = std::chrono::high_resolution_clock::now();
    // get curve generator
    REccBrick brick_=prf_.getBrick(); 
    REllipticCurve _curve=prf_.getCurve(); 
    for (size_t i = 0; i < num_server_elements; i++) {
      BitVector bv; 
      bv.assign(elements[i]); 
      REccNumber b(_curve, prf_.geta0()); 
      //  auto timea = std::chrono::high_resolution_clock::now();

      for (size_t j = 0; j < entries; ++j) {
        size_t idx=0;
        for(size_t k=0; k<factor; ++k)
          idx|=(bv[(j*factor)+k]<<k);
        if (idx) {
          b*=lut[idx-1]; 
        }
      }
      REccPoint result=brick_*b; 
      result.toBytes(prfOut[i].data());  

      //  auto timeb = std::chrono::high_resolution_clock::now();
      //  std::chrono::duration<double> tim = timeb - timea;
      //  Log::v("PRF", "Time:\n\t%fsec",
      //      tim.count()); 
    }
    // make some space in memory
    elements.clear();
    CuckooFilter cf(num_server_elements);

    auto time1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> lut_time = time0 - timex;
    std::chrono::duration<double> enc_time = time1 - time0;
    // Log::v("PSI",
    //     "Setup Time:\n\t%fsec LUT\t%fsec ENC\n",
    //     lut_time.count(), enc_time.count());

    for (size_t i = 0; i < num_server_elements; i++) {
      auto success = cf.Add((uint64_t*)prfOut[i].data());
      (void)success;
      assert(success == cuckoofilter::Ok);
      // std::cout<<"added " <<i<<std::endl; 
    }
    auto time2 = std::chrono::high_resolution_clock::now();
    prfOut.clear();  // free some memory
    auto time3 = std::chrono::high_resolution_clock::now();
    num_server_elements = htobe64(num_server_elements);
    channel_.send((uint8_t *)&num_server_elements, sizeof(num_server_elements));

    // send cuckoofilter in steps to save memory
    const uint64_t size_in_tags = cf.SizeInTags();
    const uint64_t step = (1 << 16);
    uint64_t uint64_send;
    uint64_send = htobe64(size_in_tags);
    channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));
    uint64_send = htobe64(step);
    channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));

    for (uint64_t i = 0; i < size_in_tags; i += step) {
      std::vector<uint8_t> cf_ser = cf.serialize(step, i);
      uint64_t cfsize = cf_ser.size();
      uint64_send = htobe64(cfsize);
      channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));
      channel_.send(cf_ser.data(), cfsize);
    }

    std::vector<unsigned __int128> hash_params =
      cf.GetTwoIndependentMultiplyShiftParams();
    for (auto &par : hash_params) {
      channel_.send((uint8_t *)&par, sizeof(par));
    }

    auto time4 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> cf_time = time2 - time1;
    std::chrono::duration<double> trans_time = time4 - time3;
    Log::v("PSI",
        "Setup Time:\n\t%fsec LUT\t%fsec ENC, %fsec CF,\n\t%fsec Setup,\n\t%fsec "
        "Trans,\n\t Setup Comm: %d bytes sent\n",
        lut_time.count(), enc_time.count(), cf_time.count(), (enc_time + cf_time).count(),
        trans_time.count(), channel_.getBytesSent());
    channel_.clearStats();
    free(lut); 
    lut=NULL; 
  }

  void ECNRPSIServerPreprocess::Base() {
    auto time3 = std::chrono::high_resolution_clock::now();
    size_t num_client_elements;
    channel_.recv((uint8_t *)&num_client_elements, sizeof(num_client_elements));
    num_client_elements_ = be64toh(num_client_elements);
    size_t numBaseOTs = 128;
    std::vector<block> baseOTs;
    BitVector baseChoices(numBaseOTs);
    baseChoices.randomize(prng_);
    baseOTs.resize(numBaseOTs);
    span<block> baseOTsSpan(baseOTs.data(), baseOTs.size());

    VerifiedSimplestOT ot;
    ot.receive(baseChoices, baseOTsSpan, prng_, channel_);
    KosOtExtSender otExtSender;
    otExtSender.setBaseOts(baseOTsSpan, baseChoices);

    ots_.resize(num_client_elements_ * 128);
    span<std::array<block, 2>> otSpan(ots_.data(), ots_.size());
    otExtSender.send(otSpan, prng_, channel_);
      auto time4 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans_time = time4 - time3;
  Log::v("PSI",
         "Base OT Time:\n\t%fsec\n"
         "Setup Comm: %ld b sent, \n",
         trans_time.count(), channel_.getBytesSent()
  );
  channel_.clearStats();
  }

  void ECNRPSIServerPreprocess::Online() {
    auto time3 = std::chrono::high_resolution_clock::now();
    std::vector<std::array<uint8_t, 32>> prfInOut;
    BitVector bv(128 * num_client_elements_);

    channel_.recv(bv.data(), num_client_elements_ * 128 / 8);
    for (auto i = 0; i < num_client_elements_; i++) {
      BitVector c;
      c.copy(bv, 128 * i, 128);
      span<std::array<block, 2>> otSpan(&ots_[i * 128], 128);
      prf_.oprf(c, otSpan, channel_);
    }
    auto time4 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> trans_time = time4 - time3;
    Log::v("PSI",
        "Online Time:\n\t%fsec\n"
        "Setup Comm: %ld b sent\n",
        trans_time.count(), channel_.getBytesSent());
    channel_.clearStats();
  }
}  // namespace droidCrypto


