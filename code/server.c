#include <sys/types.h>  
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <limits.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "rng.h"
#include "csidh.h"
#include "network-utils.h"

#ifndef HASHLEN
#define HASHLEN 128
#endif

private_key server_keys[HASHLEN+1];
void init(){
  for(int32_t i=0; i<HASHLEN+1;++i){ 
    csidh_private(&server_keys[i]);
  }
}

void *evaluate(int csocket){
  large_private_key R={0};
  for(size_t i=0; i<HASHLEN; ++i){
    public_key client_eval={0}; 
    recv(csocket, &client_eval, sizeof(client_eval), 0);
    Response response;
    private_key blinder;
    csidh_private(&blinder);
    csidh(&response.E[0], &client_eval, &blinder);
    csidh(&response.E[1], &response.E[0], &(server_keys[i+1]));
    send(csocket, &response, sizeof(response), 0);
    sub_large_key(&R, &blinder);
  }
  //// finalize ////
  public_key finalize={0}; 
  recv(csocket, &finalize, sizeof(finalize), 0);
  add_large_key(&R, &(server_keys[0]));
  large_csidh(&finalize, &finalize, &R);
  send(csocket, &finalize, sizeof(finalize), 0);
  close(csocket);
  return NULL;
}

int main(int argc, char **argv){
  if(argc != 2){
    puts("usage: port"); 
    return -1; 
  }
  //////////////////////////////////////////////
  /////////////////// Socket setup /////////////
  //////////////////////////////////////////////

  size_t port=atoll(argv[1]); 
  if(port==0){
    puts("Port needs to be a nonzero integer. "); 
    return -1; 
  }
  else if(port>=(1<<16)){
    puts("Port needs to be an integer in the range 1--(1<<16-1)");
    return -1; 
  }

  init();

  struct sockaddr_in s;
  memset((void*)&s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_port = htons(port);
  int serversocket; 

  struct sockaddr other;
  socklen_t otherlen = sizeof(struct sockaddr);
  serversocket = socket(AF_INET, SOCK_STREAM, 0);
  int reuse = 1;
  setsockopt(serversocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
      sizeof(reuse));

  if(bind(serversocket, (struct sockaddr *)&s,
        sizeof(struct sockaddr))==-1){
    perror("Socket Bind failed");
    return -1;
  }
  if (listen(serversocket, INT_MAX)==-1){
    perror("Socket Listen failed");
    return -1;
  }


  //////////////////////////////////////////////
  //////////// Keygen and KAT //////////////////
  //////////////////////////////////////////////
  init();
//  bool msg[HASHLEN];
//
//  for(size_t i=0; i<HASHLEN; i++)
//    msg[i]=(bool)(i%2);
//
//  // KAT
//  public_key server_result;
//  large_private_key aggregated={0};
//  // compute inital
//  add_large_key(&aggregated,&(server_keys[0]));
//
//  for(size_t i=0; i<HASHLEN; ++i){
//    if(msg[i]){
//      // equivalent to csidh(&server_result, &server_result, &server_keys[i+1]);
//      add_large_key(&aggregated, &(server_keys[i+1]));
//    }
//  }
//  large_csidh(&server_result, &base, &aggregated);
//  puts("SERVER RESULT"); 
//  uint_print(&server_result.A); 

  //////////////////////////////////////////////
  /////////////////// OPRF /////////////////////
  //////////////////////////////////////////////
  while(1){
    int csocket = accept(serversocket, (struct sockaddr *)&other, &otherlen);
    if(csocket == -1){
      perror("accept failed");
      return -1;
    }
    pthread_t tid;
    if (pthread_create(&tid, NULL, evaluate,csocket)!=0){
      perror("thread could not be created");
    }
    pthread_detach(tid);
  }

  return 0; 
}

