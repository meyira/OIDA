#include <sys/types.h>  
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "rng.h"
#include "csidh.h"


int main(int argc, char **argv){
  if(argc != 4){
    puts("usage: IP, port, is_server"); 
    return -1; 
  }
  //////////////////////////////////////////////
  /////////////////// Socket setup /////////////
  //////////////////////////////////////////////

  char* hostname=argv[1]; 
  size_t port=htons(atoll(argv[2])); 
  bool is_server=(bool)atoll(argv[3]); 
  int csocket; 

  struct sockaddr_in s;
  memset((void*)&s, 0, sizeof(s));
  s.sin_family = AF_INET;
  if (!is_server)
    s.sin_addr.s_addr = inet_addr(hostname);
  s.sin_port = htons(port);
  int serversocket; 

  if (is_server) {
    struct sockaddr other;
    socklen_t otherlen = sizeof(struct sockaddr);
    serversocket = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(serversocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
        sizeof(reuse));

    bind(serversocket, (struct sockaddr *)&s,
        sizeof(struct sockaddr));
    listen(serversocket, 1);
    csocket = accept(serversocket, (struct sockaddr *)&other, &otherlen);

  } else {
    csocket = socket(AF_INET, SOCK_STREAM, 0);
    while (connect(csocket, (struct sockaddr *)&s,
          sizeof(struct sockaddr)) < 0);
  }
  //////////////////////////////////////////////
  //////////// Keygen and KAT //////////////////
  //////////////////////////////////////////////
        const size_t HASHLEN=128;
  private_key server_keys[HASHLEN+1];
    bool msg[HASHLEN];
  if(is_server){
    for(size_t i=0; i<(HASHLEN+1); i++){
      csidh_private(&server_keys[i]);
    }
  }
  //else{
    for(size_t i=0; i<HASHLEN; i++)
      msg[i]=(bool)rand()%2;

  //}
  // KAT
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
      uint_print(&server_result.A); 


    //////////////////////////////////////////////
    /////////////////// OPRF /////////////////////
    //////////////////////////////////////////////
    size_t ret=0;
    if(is_server){
      public_key pk; 

        csidh(&pk, &base, &server_keys[0]);
        send(csocket, &pk, sizeof(public_key), 0);
      for(size_t i=0; i<HASHLEN; ++i){
        recv(csocket, &pk, sizeof(public_key), 0);
        csidh(&pk, &pk, &server_keys[i+1]);
        send(csocket, &pk, sizeof(public_key), 0);
      }
    }
    else{
      public_key to_server;
      large_private_key unblind={0};
      public_key client_result; // TODO init if OPUS-simple, change if robust
        recv(csocket, &client_result, sizeof(public_key), 0);
      for(size_t i=0; i<HASHLEN; ++i){
        private_key blinder={0};
        csidh_private(&blinder);
        ret= csidh(&to_server, &client_result, &blinder); ;
        send(csocket, &to_server, sizeof(public_key), 0);
        recv(csocket, &to_server, sizeof(public_key), 0);
                            if(msg[i]){
                            // unblind and update
                            sub_large_key(&unblind, blinder);
                            memcpy(&client_result, &to_server, sizeof(public_key));
                    }


      }
      large_csidh(&client_result, &client_result, &unblind);
      uint_print(&client_result.A); 

    }
    close(csocket);

    return 0; 
}

