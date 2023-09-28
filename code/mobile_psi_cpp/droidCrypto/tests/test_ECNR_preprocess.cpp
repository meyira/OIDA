#include <assert.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/SecureRandom.h>
#include <droidCrypto/BitVector.h>
#include <chrono>
#include <droidCrypto/psi/tools/ECNRPRF.h>
#include <droidCrypto/utils/Log.h>
using namespace droidCrypto; 

int main(void){
    PRNG prng_(PRNG::getTestPRNG());
    size_t hashlen=128; 
    ECNRPRF prf_(prng_, hashlen);

  std::vector<droidCrypto::block> elements;
  SecureRandom rnd;
  // 2^15
  for(size_t i = 0; i < (2<<21); i++) {
    elements.push_back(rnd.randBlock());
  }
  auto keys=prf_.getKeys(); 
  size_t num_server_elements = elements.size();
  std::vector<std::array<uint8_t, 33>> prfOut(num_server_elements);
  REllipticCurve _curve=prf_.getCurve(); 
  REccBrick brick_=prf_.getBrick(); 


  auto timea = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < num_server_elements; i++) {
    BitVector bv; 
    bv.assign(elements[i]); 
    REccNumber b(_curve, prf_.geta0()); 
    for(size_t j=0; j<hashlen; ++j){
      if(bv[j])
        b *= keys[j]; 
    }

    REccPoint result=brick_*b; 
    result.toBytes(prfOut[i].data());  
  }

  auto timeb = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> noopt = timeb - timea;
  Log::v("PSI",
      "No optimization:\n\t\t%fsec ENC\n",
      noopt.count());

  for (size_t factor=2; factor<=16; factor=factor*2){
    // preprocess keys
    auto timex = std::chrono::high_resolution_clock::now();
    size_t entries=hashlen/factor; 
    REccNumber *lut=(REccNumber*)calloc(sizeof(REccNumber),entries*((1ULL<<factor)-1));   //start filling at 1 as 0 will have no effect; 
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
    }
    auto time1 = std::chrono::high_resolution_clock::now();



    std::chrono::duration<double> lut_time = time0 - timex;
    std::chrono::duration<double> enc_time = time1 - time0;
    Log::v("PSI",
        "Setup Time factor %d :\n\t%fsec LUT\t%fsec ENC\n",
        factor, lut_time.count(), enc_time.count());

    free(lut); 
    lut=NULL; 
  }
}

