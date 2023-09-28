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

void add_key(private_key *res, private_key k1){
  // TODO inline?
  for(size_t i=0; i<NUM_PRIMES; ++i){
    res->e[i]+=k1.e[i];
  }
}

 void prf_add(){
   private_key server_keys[512]; 
   private_key additive={0}; 
   for(size_t i=0; i<(512); i++){
     csidh_private(&server_keys[i]); 
     add_key(&additive,server_keys[i]);
   }

   public_key equiv; 
   csidh(&equiv, &base, &additive); 

   public_key control; 
   // printf("used %ld keys\n", keys+1); 
   csidh(&control, &base, &server_keys[0]); 
   for(size_t i=1; i<512; ++i)
     csidh(&control, &control, &server_keys[i]); 

  if(memcmp(&control, &equiv, sizeof(public_key))){
    puts("\nNot Equal");
    puts("got");
   // uint_print(&equiv.A);
    puts("Expected");
   // uint_print(&control.A);
    return false;
  }
  return true;
 }

int main(void){
  // generate KAT
  prf_add(); 
  return 0; 
}


