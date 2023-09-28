#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "rng.h"
#include "csidh.h"

clock_t keygen_t;
clock_t prf_t;
clock_t oprf_t;
clock_t s_oprf_t;
const size_t HASHLEN[3]={128,256,512}; 

void uint_s_print(uint_s const *x)
{
  for (size_t i = 8*LIMBS-1; i < 8*LIMBS; --i)
    printf("%02hhx", i[(unsigned char *) x->c]);
  puts("");
}

void prf(private_key *keys, bool* msg, size_t h){
  clock_t t0, t1;
  t0 = (float)clock();
  public_key server_result;
  large_private_key aggregated={0};
  // compute inital
  add_large_key(&aggregated,&keys[0]);

  for(size_t i=0; i<h; ++i){
    if(msg[i]){
      // equivalent to csidh(&server_result, &server_result, &server_keys[i+1]);
      add_large_key(&aggregated, &keys[i+1]);
    }
  }
  large_csidh(&server_result, &base, &aggregated);
  t1 = (float)clock();
  // puts("PRF");
  // uint_s_print(&server_result.A);

  prf_t+=t1-t0; 
}

void opus(private_key *keys, bool* msg, size_t h){
  clock_t t0, t1;
  clock_t tt0, tt1;

  t0 = (float)clock();
  public_key client_result={0};
  public_key s_E_0, s_E_1;
  large_private_key unblind_s={0};
  large_private_key unblind_c={0};

  for(size_t i=0; i<h; ++i){
    //////////////////////////////////////////////////////
    //////////////////////////Client//////////////////////
    //////////////////////////////////////////////////////
    private_key blinder={0};
    csidh_private(&blinder);
    csidh(&client_result, &client_result, &blinder);

    //////////////////////////////////////////////////////
    //////////////////////////Server//////////////////////
    //////////////////////////////////////////////////////
    tt0 = (float)clock();
    private_key rs={0}; 
    csidh_private(&rs); 
    csidh(&s_E_0, &client_result, &rs);
    csidh(&s_E_1, &s_E_0, &keys[i+1]);
    sub_large_key(&unblind_s, &rs);
    tt1 = (float)clock();
    s_oprf_t+=tt1-tt0; 

    //////////////////////////////////////////////////////
    //////////////////////////Client//////////////////////
    //////////////////////////////////////////////////////
    sub_large_key(&unblind_c, &blinder);
    if(msg[i]){
      memcpy(&client_result, &s_E_1, sizeof(public_key));
    }
    else{
      memcpy(&client_result, &s_E_0, sizeof(public_key));
    }
  }
  /////////////////////////////////////////////////////////
  ///////////////// Finalize //////////////////////////////
  /////////////////////////////////////////////////////////
  private_key rc={0}; 
  csidh_private(&rc);
  csidh(&client_result, &client_result, &rc);

  tt0 = (float)clock();
  add_large_key(&unblind_s, &keys[0]);
  large_csidh(&client_result, &client_result, &unblind_s);
  tt1 = (float)clock();

  sub_large_key(&unblind_c, &rc);
  large_csidh(&client_result, &client_result, &unblind_c);

  s_oprf_t+=tt1-tt0; 
  t1 = (float)clock();
  oprf_t+=t1-t0; 
  //puts("OPUS"); 
  //uint_s_print(&client_result.A);

}

/* defaults */
int main()
{
  float runs=100;
  remove("benchmarks.txt");
  for(size_t h=0; h<3; ++h){
    bool msg[HASHLEN[h]];
    private_key server_keys[HASHLEN[h]+1];
    keygen_t=0;
    prf_t=0;
    oprf_t=0;
    s_oprf_t=0;
    for(size_t s=0; s<runs; ++s){
      time_t t0 = (float)clock();
      for(size_t i=0; i<(HASHLEN[h]+1); i++){
        csidh_private(&server_keys[i]);
      }
      time_t t1 = (float)clock();
      keygen_t+=t1-t0; 
      for(size_t i=0; i<HASHLEN[h]; i++)
        msg[i]=rand()%2;
      prf(server_keys, msg, HASHLEN[h]); 
      opus(server_keys, msg, HASHLEN[h]); 
    }
    FILE *bench = fopen("benchmarks.txt", "a");
    printf( "---------------------------------------- %ld bits ----------------------------------------\n",HASHLEN[h]);
    printf("Keygen took %f cycles = %f ms\n", keygen_t/runs, (keygen_t/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("PRF Evaluation took %f cycles = %f ms\n", prf_t/runs, (prf_t/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("OPUS client took %f cycles = %f ms\n", (oprf_t-s_oprf_t)/runs, ((oprf_t-s_oprf_t)/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("OPUS server took %f cycles = %f ms\n", s_oprf_t/runs, (s_oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("OPUS took %f cycles = %f ms\n", oprf_t/runs, (oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 

    if(bench==NULL) {
      perror("Error opening file.");
    }
    else{
      fprintf(bench, "---------------------------------------- %ld bits ----------------------------------------\n",HASHLEN[h]);
      fprintf(bench, "Keygen took %f cycles = %f ms\n", keygen_t/runs, (keygen_t/runs)/(CLOCKS_PER_SEC/1000)); 
      fprintf(bench, "PRF Evaluation took %f cycles = %f ms\n", prf_t/runs, (prf_t/runs)/(CLOCKS_PER_SEC/1000)); 
      fprintf(bench, "OPUS client took %f cycles = %f ms\n", (oprf_t-s_oprf_t)/runs, ((oprf_t-s_oprf_t)/runs)/(CLOCKS_PER_SEC/1000)); 
      fprintf(bench, "OPUS server took %f cycles = %f ms\n", s_oprf_t/runs, (s_oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 
      fprintf(bench, "OPUS took %f cycles = %f ms\n", oprf_t/runs, (oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 
    }
    fclose(bench);
  }
  return 0; 
}

