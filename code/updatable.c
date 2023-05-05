#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>

#include "rng.h"
#include "csidh.h"

int main()
{
  clock_t t0, t1;
  remove("updateable.csv");

  const size_t HASHLEN=256; 
  bool msg[HASHLEN];
  private_key server_keys[HASHLEN+1];
  float runs=100;
  const size_t R=256;
  uint8_t idx[256];
  bool free[HASHLEN];

  for(size_t update=1; update<256; ++update){
    clock_t recompute_t=0;
    clock_t update_t=0;
    printf("STARTING ROUND %ld \n\n", update);
    for(size_t s=0; s<runs; ++s){
      /*
       * sample fresh keys
       */
      for(size_t i=0; i<(HASHLEN+1); i++){
        csidh_private(&server_keys[i]);
      }
      for(size_t i=0; i<update; ++i){
        free[i]=1;
      }
      for(size_t i=0; i<HASHLEN; i++)
        msg[i]=(bool)(rand()%2);

      /*
       * Compute initial OPRF
       */
      public_key server_result;
      {
        large_private_key aggregated={0};
        add_large_key(&aggregated,&server_keys[0]);

        for(size_t i=0; i<HASHLEN; ++i){
          if(msg[i]){
            add_large_key(&aggregated, &server_keys[i+1]);
          }
        }
        bool ret=large_csidh(&server_result, &base, &aggregated);
        assert(ret);
      }

      /*
       * Compute flip indices
       */
      for(size_t i=0; i<update; ++i){
        uint8_t r=(uint8_t) rand();
        while(!free[r])
          // stupid rejection sampling
          r=(uint8_t) rand();
        idx[i]=r;
        free[r]=0;
      }

      /*
       * updates
       */
      t0 = clock();
      public_key opt; 
      {
        large_private_key updater={0};
        for(size_t i=0; i<update; ++i){
          // invert keys
          if(msg[idx[i]])
            sub_large_key(&updater, &server_keys[idx[i]+1]);
          else
            add_large_key(&updater, &server_keys[idx[i]+1]);
        }
        bool ret=large_csidh(&opt, &server_result, &updater);
        assert(ret);
      }
      t1 = clock();
      update_t+=t1-t0; 

      /*oprf-opt
       * recompute
       */
      t0 = clock();
      public_key recomp;
      {
        large_private_key aggregated2={0};
        add_large_key(&aggregated2,&server_keys[0]);
        for(size_t i=0; i<update; ++i){
          msg[idx[i]]=!msg[idx[i]];
        }
        for(size_t i=0; i<HASHLEN; ++i){
          if(msg[i]){
            add_large_key(&aggregated2, &server_keys[i+1]);
          }
        }
        bool ret=large_csidh(&recomp, &base, &aggregated2);
        assert(ret);
      }
      t1 = clock();
      recompute_t+=(t1-t0); 

      //// verification, annoying when doing benchmarking
      //if (memcmp(&opt, &recomp, sizeof(public_key))){
      //  printf("\x1b[31mNOT EQUAL!\x1b[0m\n");
      //}
      //else
      //  printf("\x1b[32mequal.\x1b[0m\n");
    }
    FILE *noopt = fopen("updateable.csv", "a");
    if(noopt==NULL) {
      perror("Error opening updatable file.");
      return -1;
    }
    fprintf(noopt, "%ld;%f;%f\n", update, recompute_t/runs, update_t/runs);
    fclose(noopt);

  }
  return 0; 
}

