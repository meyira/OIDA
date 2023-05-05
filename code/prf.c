#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>

#include "csidh.h"

bool prf_opt(bool msg[], private_key *server_keys, size_t length){

  public_key server_result;
  large_private_key aggregated={0};
  // compute inital
  add_large_key(&aggregated,&server_keys[0]);

  for(size_t i=0; i<length; ++i){
    if(msg[i]){
      // equivalent to csidh(&server_result, &server_result, &server_keyss[i+1]);
      add_large_key(&aggregated, &server_keys[i+1]);
    }
  }
  large_csidh(&server_result, &base, &aggregated);

  return true;
}

bool prf(bool msg[], private_key *server_keys, size_t length){
  public_key server_result; 
  csidh(&server_result, &base, &server_keys[0]); 
  for(size_t i=0; i<length; ++i){                
    if(msg[i]){
      csidh(&server_result, &server_result, &server_keys[i+1]); 
    }
  }
  return true; 
}

int main(void){
  bool msg[512]; 
  int runs=0; 
  double prf_time=0;
  double opt_time=0;
  clock_t startTime, endTime;
  remove("noopt.txt");
  remove("opt.txt");
  for(size_t k=0; k<512; k++){
          FILE *noopt = fopen("noopt.csv", "a");
          if(noopt==NULL) {
                  perror("Error opening noopt file.");
                  return -1; 
          }
          private_key *server_keys=(private_key*)calloc(sizeof(private_key), k+1);
          for(size_t runs=0; runs<100; ++runs){
                  for(size_t i=0; i<(k); i++){
                          csidh_private(&server_keys[i]);
                  }
                  csidh_private(&server_keys[k]);

                  for(size_t i=0; i<k; i++)
                          msg[i]=rand()%2; 
                  startTime = clock();
                  prf(msg, server_keys, k); 
                  endTime = clock();

                  prf_time += (double)(endTime - startTime)/CLOCKS_PER_SEC;
                  startTime = clock();
                  prf_opt(msg, server_keys, k); 
                  endTime = clock();
                  opt_time += (double)(endTime - startTime)/CLOCKS_PER_SEC;
          }
          fprintf(noopt, "%ld;%f;%f\n", k, prf_time/100, opt_time/100);
          free(server_keys); 
          server_keys=NULL;
          fclose(noopt);
          printf("finished %ld\n", k); 
  }
  return 0; 
}
