#include "opaque-common.h"

uint64_t rdtsc() {
  uint64_t a, d;
  __asm__ volatile("mfence");
  __asm__ volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
  a = (d << 32) | a;
  __asm__ volatile("mfence");
  return a;  
}

void debug_print(const char *name, const unsigned char *m, size_t m_len) {
  printf("%s:\n", name);
  for(size_t i = 0; i < m_len; i++) {
    printf("%02hhx", m[i]);
  }
  printf("\n\n");
}

int setup_socket_s(int *serversocket, uint16_t port) {
  struct sockaddr_in s;
  memset((void *) &s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_port = htons(port);

  *serversocket = socket(AF_INET, SOCK_STREAM, 0);
  int reuse = 1;
  setsockopt(*serversocket, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));

  if(bind(*serversocket, (struct sockaddr *) &s, sizeof(struct sockaddr)) != 0) {
    printf("Bind failed\n");
    return -1; 
  }
  if(listen(*serversocket, 1) != 0) {
    printf("Listen failed\n");
    return -1;
  } 
  
  return 0;
}

void setup_socket_c(int *csocket, const char *hostname, uint16_t port) {
  struct sockaddr_in s;
  memset((void *) &s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_addr.s_addr = inet_addr(hostname);
  s.sin_port = htons(port);

  *csocket = socket(AF_INET, SOCK_STREAM, 0);
  while(connect(*csocket, (struct sockaddr *) &s, sizeof(struct sockaddr)) < 0)
    ;
}

int read_len(int socket, unsigned char *buf, ssize_t length, const char *info) {
  ssize_t total = 0;
  while(total != length) {
    ssize_t len = recv(socket, buf + total, length - total, 0); 
    if(len == -1) {
      printf("Invalid %s: %ld vs %ld\n", info, length, total);
      return -1;
    }
    total += len;
  }

  return 0;
}
