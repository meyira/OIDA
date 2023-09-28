#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <inttypes.h>

#include "uint.h"
#include "fp.h"
#include "mont.h"
#include "csidh.h"
#include "rng.h"
//#include "pq-ot/pq-ot.h"

#define HASHLEN 128 

void add_large_key(large_private_key *res, private_key k1){
  // TODO inline?
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]+=k1.e[i];
  }
}

void add_key(private_key *res, private_key k1){
  // TODO inline?
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]+=k1.e[i];
  }
}

void prf_lut(){
  bool msg[HASHLEN]; 
  private_key server_keys[HASHLEN+1]; 
  for(size_t i=0; i<(HASHLEN+1); i++){
    csidh_private(&server_keys[i]); 
  }

  size_t factor=16;
  size_t entries=HASHLEN/factor;
  private_key *lut=(private_key*)calloc(sizeof(private_key),entries*((1ULL<<factor)-1));   //start filling at 1 as 0 will have no effect

  // for each blocks
  size_t key_idx=0; 
  for(size_t i=0; i<entries; ++i){
    // for each possible combination
    size_t val=1;
    for(size_t j=0; j<((1ULL<<factor)-1); ++j){
      // add each key
      for(size_t k=0; k<factor; ++k){
        if(val & (1ULL<<k)){
          add_key(&lut[(((1ULL<<factor)-1)*i)+val-1], server_keys[key_idx+k+1]);
        }
      }
      ++val;
    }
    key_idx+=factor; 
  }


  //  for(size_t x=0; x<100; x++){
  for(size_t i=0; i<HASHLEN; i++){
    msg[i]=rand()%2;
  }

  public_key prfOut={0}; 
  large_private_key final; 
  for(size_t k=0; k<NUM_PRIMES; ++k)
    final.e[k]=server_keys[0].e[k]; 

  size_t scaler=(1ULL<<factor)-1; 
  for (size_t i = 0; i < entries; ++i) {
    size_t idx=0; 
    for(size_t j=0; j<factor; ++j)
      idx|=(msg[(i*factor)+j]<<j); 
    if (idx) {
      // leave out any 0000 blocks
      add_large_key(&final, lut[(scaler*i)+idx-1]);
    }
  }
      large_csidh(&prfOut, &base, &final);
  free(lut); 
  lut=NULL; 

  // CONTROL GROUP
  public_key control={0}; 

  csidh(&control, &base, &server_keys[0]); 
  for(size_t i=0; i<HASHLEN; i++){
    if(msg[i]){
      csidh(&control, &control, &server_keys[i+1]); 
    }
  }

  if(memcmp(&control, &prfOut, sizeof(public_key))){
    puts("\nNot Equal");
    puts("got");
    uint_print(&prfOut.A);
    puts("Expected");
    uint_print(&control.A);
    return false;
  }
  puts("success");
  return true;
}

// void prf_add(){
// 
//   bool msg[HASHLEN]; 
//   private_key server_keys[HASHLEN+1]; 
//   for(size_t i=0; i<(HASHLEN+1); i++){
//     csidh_private(&server_keys[i]); 
//   }
//   clock_t startTime = clock();
// 
//   for(size_t x=0; x<100; x++){
//     for(size_t i=0; i<HASHLEN; i++)
//       msg[i]=rand()%2;
//     public_key server_result; 
//     // only need 11 on average, those are for all 1's
//     private_key final[26]={0}; 
//     // compute inital
//     add_key(&final[0],server_keys[0]); 
//     // counters for addressing
//     size_t keys=0; 
//     size_t used=1;  
// 
//     for(size_t i=0; i<HASHLEN; ++i){
//       if(msg[i]){
//         //  csidh(&server_result, &server_result, &server_keys[i+1]); 
//         add_key(&final[keys], server_keys[i+1]); 
//         ++used; 
//         if(used==6){
//           ++keys; 
//           used=0; 
//         }
//       }
//     }
//     // printf("used %ld keys\n", keys+1); 
//     csidh(&server_result, &base, &final[0]); 
//     for(size_t i=1; i<=keys; ++i)
//       csidh(&server_result, &server_result, &final[i]); 
// 
//   }
//   clock_t endTime = clock();
// 
//   double timeElapsed = (double)(endTime - startTime)/CLOCKS_PER_SEC;
//   printf("PRF with key addion done in %f seconds\n", timeElapsed);
// }

int main(void){
  // generate KAT
  prf_lut(); 
  //prf_add(); 
  return 0; 
}


