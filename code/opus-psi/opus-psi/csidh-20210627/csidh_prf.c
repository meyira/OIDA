#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>

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

void sub_large_key(large_private_key *res, private_key k1){
  // TODO inline?
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]-=k1.e[i];
  }
}
void add_key(private_key *res, private_key k1){
  // TODO inline?
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]+=k1.e[i];
  }
}
void sub_key(private_key *res, private_key k1){
  // TODO inline?
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]-=k1.e[i];
  }
}

bool prf_opt(bool msg[], private_key *server_keys){

  public_key server_result;
  large_private_key aggregated={0};
  // compute inital
  add_large_key(&aggregated,server_keys[0]);

  for(size_t i=0; i<HASHLEN; ++i){
    if(msg[i]){
      // equivalent to csidh(&server_result, &server_result, &server_keyss[i+1]);
      add_large_key(&aggregated, server_keys[i+1]);
    }
  }
  large_csidh(&server_result, &base, &aggregated);

  return true;
}

bool prf(bool msg[], private_key *server_keys){
  ////////////////////////////////////////////////////////////////////
  ///////////////////////// SETUP PHASE //////////////////////////////
  ////////////////////////////////////////////////////////////////////
  //ignore cuckoo filter, just compute server result

  public_key server_result; 
  csidh(&server_result, &base, &server_keys[0]); 
  for(size_t i=0; i<HASHLEN; ++i){
    if(msg[i]){
      csidh(&server_result, &server_result, &server_keys[i+1]); 
    }
  }
  return true; 
}

int main(void){
  private_key *server_keys=(private_key*)calloc(sizeof(private_key), HASHLEN+1);
  // generate KAT
  ////////////////////////////////////////////////////////////////////
  ///////////////// SERVER RANDOM KEY ////////////////////////////////
  ////////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////
  ///////////////// RANDOM ///////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////

  bool msg[128]; 
  int runs=0; 
  double prf_time=0;
  double opt_time=0;
  clock_t startTime, endTime;
  while(runs<100){
    for(size_t i=0; i<(HASHLEN+1); i++){
      csidh_private(&server_keys[i]);
    }
    for(size_t i=0; i<HASHLEN; i++)
      msg[i]=rand()%2; 
    startTime = clock();
    prf(msg, server_keys); 
    endTime = clock();

    prf_time += (double)(endTime - startTime)/CLOCKS_PER_SEC;
    startTime = clock();
    prf_opt(msg, server_keys); 
    endTime = clock();
    opt_time += (double)(endTime - startTime)/CLOCKS_PER_SEC;

    runs++;
  }
  printf("normal prf took %f seconds\n", prf_time/runs);
  printf("optimized prf took %f seconds\n", opt_time/runs);
  return 0; 
}

// same but with OPRF
//bool prf_opt(bool msg[], private_key *server_keys, private_key *server_random_two){
//
//  ////////////////////////////////////////////////////////////////////
//  /////////////////////// Client R-OT ////////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//  bool client_choices[HASHLEN];
//  private_key client_randomness[HASHLEN];
//  for(size_t i=0; i<HASHLEN; i++){
//    // some bad random numbers
//    client_choices[i]=rand()%2;
//    for(size_t k=0; k<NUM_PRIMES; ++k){
//      // copy key
//      client_randomness[i].e[k]=server_random_two[2*i+client_choices[i]].e[k];
//    }
//  }
//
//  ////////////////////////////////////////////////////////////////////
//  ///////////////////////// SETUP PHASE //////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//  //ignore cuckoo filter, just compute server result for checking
//
//  public_key server_result;
//  large_private_key aggregated={0};
//  // compute inital
//  add_large_key(&aggregated,server_keys[0]);
//
//  for(size_t i=0; i<HASHLEN; ++i){
//    if(msg[i]){
//      // equivalent to csidh(&server_result, &server_result, &server_keyss[i+1]);
//      add_large_key(&aggregated, server_keys[i+1]);
//    }
//  }
//  large_csidh(&server_result, &base, &aggregated);
//
//  ////////////////////////////////////////////////////////////////////
//  ///////////////////////// Online PHASE //////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//
//  //compute correction bits
//  bool client_correction_bits[HASHLEN];
//  for(size_t i=0; i<HASHLEN; i++){
//    client_correction_bits[i]=client_choices[i]^msg[i];
//  }
//
//  //compute randomness with key
//  private_key Rij[HASHLEN];
//  for(size_t i=0; i<HASHLEN; i++){
//    // compute r_{1-c}^(r_c+k)
//    for(size_t k=0; k<NUM_PRIMES; ++k){
//      // other(non-chosen) r
//      Rij[i].e[k]=server_random_two[2*i+1-client_correction_bits[i]].e[k];
//      // xor with chosen r and k
//      Rij[i].e[k]^=(server_random_two[2*i+client_correction_bits[i]].e[k]+ server_keys[i+1].e[k]);
//    }
//  }
//
//  public_key gi={0};
//  large_private_key fin={0};
//  // compute inital
//  add_large_key(&fin,server_keys[0]);
//
//  for(size_t i=0; i<HASHLEN; i++){
//    // invert asked bit
//    sub_large_key(&fin, server_random_two[2*i+client_correction_bits[i]]);
//  }
//  large_csidh(&gi, &base, &fin);
//
//
//  ////////////////////////////////
//  //////// correct Rij   /////////
//  ////////////////////////////////
//  large_private_key large={0};
//  for(size_t i=0; i<HASHLEN; i++){
//    if(msg[i]){
//      private_key tmp;
//      for(size_t k=0; k<NUM_PRIMES; ++k){
//        tmp.e[k]=client_randomness[i].e[k];
//        tmp.e[k]^=Rij[i].e[k];
//      }
//      add_large_key(&large, tmp);
//    }
//    else{
//      add_large_key(&large, client_randomness[i]);
//    }
//  }
//  large_csidh(&gi, &gi, &large);
//
//  ////////////////////////////////
//  //////// verify result /////////
//  ////////////////////////////////
//  // if(memcmp(&gi, &server_result, sizeof(public_key))){
//  //   puts("\nNot Equal");
//  //   puts("got");
//  //   uint_print(&gi.A);
//  //   puts("Expected");
//  //   uint_print(&server_result.A);
//  //   return false;
//  // }
//  return true;
//}
//
//bool prf(bool msg[], private_key *server_keys, private_key *server_random_two){
//  ////////////////////////////////////////////////////////////////////
//  ///////////////////////// BASE PHASE ///////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//  //if (role==SERVER){//ALICE, sender
//
//  /*
//   * generate random element, private key and public key
//   */
//  //uint8_t NR_OT=(HASHLEN+7)/(sizeof(mp_limb_t)*8); 
//
//
//  //---------CLIENT r-ot---------------------
//  bool client_choices[HASHLEN]; 
//  private_key client_randomness[HASHLEN]; 
//  for(size_t i=0; i<HASHLEN; i++){
//    // some bad random numbers
//    client_choices[i]=0; 
//    for(size_t k=0; k<NUM_PRIMES; ++k){
//      // copy key
//      client_randomness[i].e[k]=server_random_two[client_choices[i]+2*i].e[k]; 
//    }
//  }
//
//
//
//
//  ////////////////////////////////////////////////////////////////////
//  ///////////////////////// SETUP PHASE //////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//  //ignore cuckoo filter, just compute server result
//
//  public_key server_result; 
//  csidh(&server_result, &base, &server_keys[0]); 
//  for(size_t i=0; i<HASHLEN; ++i){
//    if(msg[i]){
//      csidh(&server_result, &server_result, &server_keys[i+1]); 
//    }
//  }
//
//  ////////////////////////////////////////////////////////////////////
//  ///////////////////////// Online PHASE //////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//
//  //compute correction bits
//  bool client_correction_bits[HASHLEN]; 
//  for(size_t i=0; i<HASHLEN; i++){
//    client_correction_bits[i]=client_choices[i]^msg[i]; 
//  }
//
//  //compute randomness with key
//  private_key Rij[HASHLEN]; 
//  for(size_t i=0; i<HASHLEN; i++){
//    for(size_t k=0; k<NUM_PRIMES; ++k){
//      // other r
//      Rij[i].e[k]=server_random_two[1-client_correction_bits[i]+2*i].e[k]; 
//      // xor with chosen r and k
//      Rij[i].e[k]^=(server_random_two[(client_correction_bits[i]+2*i)].e[k] + server_keys[i+1].e[k]); 
//
//    }
//  }
//
//  // compute gi
//  public_key gi; 
//  csidh(&gi, &base, &server_keys[0]); 
//  for(size_t i=0; i<HASHLEN; i++){
//    private_key negated; 
//    // invert asked bit
//    for(size_t k=0; k<NUM_PRIMES; ++k){
//      negated.e[k]=-server_random_two[client_correction_bits[i]+2*i].e[k]; 
//    }
//    csidh(&gi, &gi, &negated); 
//  }
//
//  //correct Rij
//
//  //private_key client_final[HASHLEN]; 
//  large_private_key client_final; 
//  for(size_t i=0; i<HASHLEN; i++){
//
//    if(msg[i]){
//      for(size_t k=0; k<NUM_PRIMES; ++k){
//        client_final.e[k]=client_randomness[i].e[k]; 
//        client_final.e[k]^=Rij[i].e[k]; 
//      }
//    }
//    else{
//      for(size_t k=0; k<NUM_PRIMES; ++k){
//        client_final.e[k]=client_randomness[i].e[k]; 
//      }
//    }
//  }
//
//  //evaluate hash function
//  for(size_t i=0; i<HASHLEN; i++){
//    large_csidh(&gi, &gi, &client_final); 
//  }
//
//  return true; 
//}
//
//int main(void){
//  private_key *server_keys=(private_key*)calloc(sizeof(private_key), HASHLEN+1);
//  private_key *server_random_two=(private_key*)calloc(sizeof(private_key), HASHLEN*2);
//  // generate KAT
//  ////////////////////////////////////////////////////////////////////
//  ///////////////// SERVER RANDOM KEY ////////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//  ///////////////// RANDOM ///////////////////////////////////////////
//  ////////////////////////////////////////////////////////////////////
//
//  bool msg[128]; 
//  int runs=0; 
//  double prf_time=0;
//  double opt_time=0;
//  clock_t startTime, endTime;
//  while(runs<100){
//  for(size_t i=0; i<(HASHLEN+1); i++){
//    csidh_private(&server_keys[i]);
//  }
//  for(size_t i=0; i<HASHLEN; i++){
//    csidh_private(&server_random_two[2*i]);
//    csidh_private(&server_random_two[2*i+1]);
//  }
//    for(size_t i=0; i<HASHLEN; i++)
//      msg[i]=rand()%2; 
//    startTime = clock();
//    prf(msg, server_keys, server_random_two); 
//    endTime = clock();
//
//    prf_time += (double)(endTime - startTime)/CLOCKS_PER_SEC;
//    startTime = clock();
//    prf_opt(msg, server_keys, server_random_two); 
//    endTime = clock();
//    opt_time += (double)(endTime - startTime)/CLOCKS_PER_SEC;
//
//    runs++;
//  }
//  printf("normal prf took %f seconds\n", prf_time/runs);
//  printf("optimized prf took %f seconds\n", opt_time/runs);
//  return 0; 
//}
//
//
