#include "utils.h"

int main(int argc, char *argv[]) {
#ifdef BENCH
  // Unbuffered stdout required for bench python script
  setvbuf(stdout, 0, _IONBF, 0);
#endif
  if(argc != 2){
    printf("Usage: ./opaque-server [PORT]\n"); 
    return -1; 
  }

#if defined DEBUG && defined BENCH
  printf("Usage of DEBUG define will impact benchmark results\n");
#endif

  UserDataBase db = {0};
  if(init_list(&db, 10) != 0) return -1;

  int sock, serversocket;
  uint16_t port = htons(atoll(argv[1])); 
  struct sockaddr other;
  socklen_t otherlen = sizeof(struct sockaddr);
  if(setup_socket_s(&serversocket, port) != 0) return -1;
  
  unsigned char shared_key[SHARED_KEY_LEN];
  
  while(1) {
    printf("Waiting for client to connect...\n");
    sock = accept(serversocket, (struct sockaddr *) &other, &otherlen);
    printf("Connected\n");
    
    char function;
    if(read_len(sock, (unsigned char *) &function, sizeof(char), "function") != 0) continue;
    
#ifdef BENCH
  uint64_t t_end;
  uint64_t t_start = rdtsc();
#endif
    if(function == 'r') {
      if(user_registration_s(sock, &db) != 0) continue;
#ifdef BENCH
      t_end = rdtsc();
#endif
    }
    else if(function == 'a') {
      if(session_s(sock, &db, shared_key) != 0) continue;
#ifdef BENCH
      t_end = rdtsc();
#endif
      debug_print("Server Shared Key", shared_key, SHARED_KEY_LEN);
    }
    else continue;
    
#ifdef BENCH
    printf("%s took %lu cycles\n", (function == 'r') ? "register" : "authentication", t_end - t_start);
#endif
  }

  close(sock);
  destroy_list(&db);
  return 0;
}
