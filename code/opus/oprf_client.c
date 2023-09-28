#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>

#include "rng.h"
#include "csidh.h"

/* defaults */
int main()
{
    clock_t t0, t1;
    clock_t tt0, tt1;
    clock_t prf_t=0;
    clock_t oprf_t=0;
    clock_t s_oprf_t=0;

    const size_t HASHLEN=128; 
    bool msg[HASHLEN];
    private_key server_keys[HASHLEN+1];
//     float runs=50;
     float runs=1;

  //  for(size_t s=0; s<runs; ++s){
            for(size_t i=0; i<(HASHLEN+1); i++){
                    csidh_private(&server_keys[i]);
            }
            for(size_t i=0; i<HASHLEN; i++)
                    msg[i]=(bool)rand()%2;


            t0 = clock();
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
            bool ret=large_csidh(&server_result, &base, &aggregated);
            assert(ret);
            t1 = clock();

            prf_t+=t1-t0; 

            t0 = clock();
            tt0 = clock();
            public_key server_k_0; // some kind of public key
            csidh(&server_k_0, &base, &server_keys[0]);
            tt1 = clock();
            s_oprf_t+=tt1-tt0; 

            public_key client_result;
            memcpy(&client_result, &server_k_0, sizeof(public_key));
            large_private_key unblind={0}; 
            for(size_t i=0; i<HASHLEN; ++i){
                    public_key to_server; 
                    //////////////////////////////////////////////////////
                    //////////////////////////Client//////////////////////
                    //////////////////////////////////////////////////////
                    private_key blinder={0};
                    csidh_private(&blinder);
                    ret= csidh(&to_server, &client_result, &blinder); ;
                    assert(ret);

                    //////////////////////////////////////////////////////
                    //////////////////////////Server//////////////////////
                    //////////////////////////////////////////////////////
                    tt0 = clock();
                    ret=csidh(&to_server, &to_server, &server_keys[i+1]);
                    assert(ret);
                    tt1 = clock();
                    s_oprf_t+=tt1-tt0; 

                    //////////////////////////////////////////////////////
                    //////////////////////////Client//////////////////////
                    //////////////////////////////////////////////////////
                    if(msg[i]){
                            // unblind and update
                            sub_large_key(&unblind, blinder); 
                            memcpy(&client_result, &to_server, sizeof(public_key));
                    }
            }
            ret=large_csidh(&client_result, &client_result, &unblind);
            assert(ret);
            t1 = clock();
            oprf_t+=t1-t0; 
   // }

    printf("Client Oblivious Evaluation took %f cycles = %f ms\n", (oprf_t-s_oprf_t)/runs, ((oprf_t-s_oprf_t)/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("Server Oblivious Evaluation took %f cycles = %f ms\n", s_oprf_t/runs, (s_oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("PRF Evaluation took %f cycles = %f ms\n", prf_t/runs, (prf_t/runs)/(CLOCKS_PER_SEC/1000)); 
    printf("Oblivious Evaluation took %f cycles = %f ms\n", oprf_t/runs, (oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 

    return 0; 
}

