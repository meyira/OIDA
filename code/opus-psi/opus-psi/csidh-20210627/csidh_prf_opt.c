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

bool prf(uint8_t msg[]){
  size_t csidh_ctr=0; 
  ////////////////////////////////////////////////////////////////////
  ///////////////////////// BASE PHASE ///////////////////////////////
  ////////////////////////////////////////////////////////////////////
  //if (role==SERVER){//ALICE, sender

  /*
   * generate random element, private key and public key
   */
  //uint8_t NR_OT=(HASHLEN+7)/(sizeof(mp_limb_t)*8); 


  clock_t startTime = clock();
  ////////////////////////////////////////////////////////////////////
  ///////////////// RANDOM ///////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////
  private_key server_random_two[HASHLEN][2]; 

  for(size_t i=0; i<HASHLEN; i++){
    csidh_private(&server_random_two[i][0]); 
    csidh_private(&server_random_two[i][1]); 
  }

  ////////////////////////////////////////////////////////////////////
  ///////////////// SERVER RANDOM KEY ////////////////////////////////
  ////////////////////////////////////////////////////////////////////
  private_key server_keys[HASHLEN+1]; 
  for(size_t i=0; i<(HASHLEN+1); i++){
    csidh_private(&server_keys[i]); 
  }

  ////////////////////////////////////////////////////////////////////
  /////////////////////// Client R-OT ////////////////////////////////
  ////////////////////////////////////////////////////////////////////
  bool client_choices[HASHLEN]; 
  private_key client_randomness[HASHLEN]; 
  for(size_t i=0; i<HASHLEN; i++){
    // some bad random numbers
    client_choices[i]=rand()%2; 
    for(size_t k=0; k<NUM_PRIMES; ++k){
      // copy key
      client_randomness[i].e[k]=server_random_two[i][client_choices[i]].e[k]; 
    }
  }

  ////////////////////////////////////////////////////////////////////
  ///////////////////////// SETUP PHASE //////////////////////////////
  ////////////////////////////////////////////////////////////////////
  //ignore cuckoo filter, just compute server result for checking

  public_key server_result; 
 large_private_key aggregated={0}; 
  // compute inital
  add_large_key(&aggregated,server_keys[0]); 

  for(size_t i=0; i<HASHLEN; ++i){
    if(msg[i]){
      // equivalent to csidh(&server_result, &server_result, &server_keys[i+1]); 
      add_large_key(&aggregated, server_keys[i+1]); 
    }
  }
  large_csidh(&server_result, &base, &aggregated); 
  ++csidh_ctr; 

  ////////////////////////////////////////////////////////////////////
  ///////////////////////// Online PHASE //////////////////////////////
  ////////////////////////////////////////////////////////////////////

  //compute correction bits
  bool client_correction_bits[HASHLEN]; 
  for(size_t i=0; i<HASHLEN; i++){
    client_correction_bits[i]=client_choices[i]^msg[i]; 
  }

  //compute randomness with key
  private_key Rij[HASHLEN]; 
  for(size_t i=0; i<HASHLEN; i++){
    // compute r_{1-c}^(r_c+k)
    for(size_t k=0; k<NUM_PRIMES; ++k){
      // other(non-chosen) r
      Rij[i].e[k]=server_random_two[i][1-client_correction_bits[i]].e[k]; 
      // xor with chosen r and k
      Rij[i].e[k]^=(server_random_two[i][client_correction_bits[i]].e[k]+ server_keys[i+1].e[k]); 
    }
  }

  public_key gi={0}; 
  large_private_key fin={0};  
  // compute inital
  add_large_key(&fin,server_keys[0]); 

  for(size_t i=0; i<HASHLEN; i++){
    // invert asked bit
    sub_large_key(&fin, server_random_two[i][client_correction_bits[i]]);
  }
  large_csidh(&gi, &base, &fin); 
  ++csidh_ctr; 


  ////////////////////////////////
  //////// correct Rij   /////////
  ////////////////////////////////
  large_private_key large={0}; 
  for(size_t i=0; i<HASHLEN; i++){
    if(msg[i]){
      private_key tmp; 
      for(size_t k=0; k<NUM_PRIMES; ++k){
        tmp.e[k]=client_randomness[i].e[k]; 
        tmp.e[k]^=Rij[i].e[k]; 
      }
      add_large_key(&large, tmp); 
    }
    else{
      add_large_key(&large, client_randomness[i]);
    }
  }
  large_csidh(&gi, &gi, &large);  
  ++csidh_ctr; 

  clock_t endTime = clock();

  double timeElapsed = (double)(endTime - startTime)/CLOCKS_PER_SEC;
  printf("Done in %f seconds\n", timeElapsed);
  printf("Used %d csidh computations\n", csidh_ctr);

  ////////////////////////////////
  //////// verify result /////////
  ////////////////////////////////
  if(memcmp(&gi, &server_result, sizeof(public_key))){
    puts("\nNot Equal"); 
    puts("got"); 
    uint_print(&gi.A); 
    puts("Expected"); 
    uint_print(&server_result.A); 
    return false; 
  }
  return true; 
}

int main(void){
  // generate KAT
  bool success; 

  uint8_t msg[HASHLEN]; 
  //some random messages
  int runs=0;
  while(runs<20){
    for(size_t i=0; i<HASHLEN; i++)
      msg[i]=rand()%2;
    success=prf(msg);
    runs++;
    if(success!=true){
      printf("ERR\n");
      return -1;
    }
  }
  return 0; 
}


