#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>



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

  ////////////////////////////////////////////////////////////
  ///////////////////// Setup Connection /////////////////////
  ////////////////////////////////////////////////////////////

#define BUF_SIZE 500
 struct addrinfo hints;
           struct addrinfo *result, *rp;
           int sfd, s;
           struct sockaddr_storage peer_addr;
           socklen_t peer_addr_len;
           ssize_t nread;
           char buf[BUF_SIZE];

           if (argc != 2) {
               fprintf(stderr, "Usage: %s port\n", argv[0]);
               exit(EXIT_FAILURE);
           }

           memset(&hints, 0, sizeof(hints));
           hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
           hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
           hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
           hints.ai_protocol = 0;          /* Any protocol */
           hints.ai_canonname = NULL;
           hints.ai_addr = NULL;
           hints.ai_next = NULL;

           s = getaddrinfo(NULL, argv[1], &hints, &result);
           if (s != 0) {
               fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
               exit(EXIT_FAILURE);
           }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully bind(2).
              If socket(2) (or bind(2)) fails, we (close the socket
              and) try the next address. */

           for (rp = result; rp != NULL; rp = rp->ai_next) {
               sfd = socket(rp->ai_family, rp->ai_socktype,
                       rp->ai_protocol);
               if (sfd == -1)
        continue;

               if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                   break;                  /* Success */

               close(sfd);
           }

           freeaddrinfo(result);           /* No longer needed */

           if (rp == NULL) {               /* No address succeeded */
               fprintf(stderr, "Could not bind\n");
               exit(EXIT_FAILURE);
           }

           /* Read datagrams and echo them back to sender */

           for (;;) {
               peer_addr_len = sizeof(peer_addr);
               nread = recvfrom(sfd, buf, BUF_SIZE, 0,
                       (struct sockaddr *) &peer_addr, &peer_addr_len);
               if (nread == -1)
                   continue;               /* Ignore failed request */

               char host[NI_MAXHOST], service[NI_MAXSERV];

               s = getnameinfo((struct sockaddr *) &peer_addr,
                               peer_addr_len, host, NI_MAXHOST,
                               service, NI_MAXSERV, NI_NUMERICSERV);
               if (s == 0)
                   printf("Received %zd bytes from %s:%s\n",
                           nread, host, service);
               else
                   fprintf(stderr, "getnameinfo: %s\n", gai_strerror(s));

               if (sendto(sfd, buf, nread, 0,
                           (struct sockaddr *) &peer_addr,
                           peer_addr_len) != nread)
                   fprintf(stderr, "Error sending response\n");
           }




  for(size_t s=0; s<runs; ++s){
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
      //////////////////////////Server//////////////////////
      //////////////////////////////////////////////////////
      tt0 = clock();
      ret=csidh(&to_server, &to_server, &server_keys[i+1]);
      assert(ret);
      tt1 = clock();
      s_oprf_t+=tt1-tt0; 
    }
    t1 = clock();
    oprf_t+=t1-t0; 
  }

  printf("Client Oblivious Evaluation took %f cycles = %f ms\n", (oprf_t-s_oprf_t)/runs, ((oprf_t-s_oprf_t)/runs)/(CLOCKS_PER_SEC/1000)); 
  printf("Server Oblivious Evaluation took %f cycles = %f ms\n", s_oprf_t/runs, (s_oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 
  printf("PRF Evaluation took %f cycles = %f ms\n", prf_t/runs, (prf_t/runs)/(CLOCKS_PER_SEC/1000)); 
  printf("Oblivious Evaluation took %f cycles = %f ms\n", oprf_t/runs, (oprf_t/runs)/(CLOCKS_PER_SEC/1000)); 

  return 0; 
}

