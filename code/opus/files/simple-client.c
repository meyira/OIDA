#include <sys/types.h>  
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <stdbool.h>

#include "rng.h"
#include "csidh.h"
#include "files/utils.h"
#ifndef HASHLEN
#define HASHLEN 128
#endif


int main(int argc, char **argv){
  double overall=0;
  double start,end;
      struct timespec now;

  if(argc != 3){
    puts("usage: IP, port"); 
    return -1; 
  }
  //////////////////////////////////////////////
  /////////////////// Socket setup /////////////
  //////////////////////////////////////////////

  char* hostname=argv[1]; 
  size_t port=atoll(argv[2]); 
  if(port==0){
    puts("Port needs to be a nonzero integer. ");
    return -1;
  }
  else if(port>=(1<<16)){
    puts("Port needs to be an integer in the range 1--(1<<16-1)");
    return -1;
  }

  struct sockaddr_in s;
  memset((void*)&s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_addr.s_addr = inet_addr(hostname);
  s.sin_port = htons(port);

  for(size_t runs=0; runs<10; ++runs){
  int csocket = socket(AF_INET, SOCK_STREAM, 0);
  while (connect(csocket, (struct sockaddr *)&s,
        sizeof(struct sockaddr)) < 0);
  clock_gettime(CLOCK_REALTIME, &now);
  start= now.tv_sec + now.tv_nsec*1e-9;
  bool msg[HASHLEN];
  for(size_t i=0; i<HASHLEN; i++)
    msg[i]=(bool)(rand()%2);

  //////////////////////////////////////////////
  /////////////////// OPRF /////////////////////
  //////////////////////////////////////////////
  large_private_key unblind={0};
  public_key client_result={0}; 
  for(size_t i=0; i<HASHLEN; ++i){
    private_key blinder={0};
    csidh_private(&blinder);
    csidh(&client_result, &client_result, &blinder); 
    send(csocket, &client_result, sizeof(client_result),0);
    sub_large_key(&unblind, &blinder);
    Response response;
    recv(csocket, &response, sizeof(response),0);
    if(msg[i]){
      // unblind and update
      memcpy(&client_result, &response.E[1], sizeof(public_key));
    }
    else{
      memcpy(&client_result, &response.E[0], sizeof(public_key));
    }
  }
  private_key blinder={0};
  csidh_private(&blinder);
  csidh(&client_result, &client_result, &blinder); 
  send(csocket, &client_result, sizeof(client_result),0);
  sub_large_key(&unblind, &blinder);
  recv(csocket, &client_result, sizeof(client_result),0);
  large_csidh(&client_result, &client_result, &unblind);
  /////// Uncomment for sanity
  puts("FINAL RESULT");
  uint_print(&client_result.A); 
  clock_gettime(CLOCK_REALTIME, &now);
  end= now.tv_sec + now.tv_nsec*1e-9;;
  overall +=(end-start);
  printf("OPRF Evaluation took %.3lf s\n", overall); 
  }

  return 0; 
}

