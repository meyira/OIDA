#include "utils.h"

int main(int argc, char *argv[]) {
  if(argc != 6) {
    printf("Usage: ./opaque-client [IP] [PORT] [username] [password] [register/authentication]\n"); 
    return -1; 
  }

#if defined DEBUG && defined BENCH
  printf("Usage of DEBUG define will impact benchmark results\n");
#endif

  int sock;
  const char *hostname = argv[1];
  uint16_t port = htons(atoi(argv[2]));
  setup_socket_c(&sock, hostname, port);
  
  const char *username = argv[3];
  const char *pw = argv[4];
  const char *function = argv[5];
  unsigned char shared_key[SHARED_KEY_LEN];
  
#ifdef BENCH
  uint64_t t_start, t_end;
#endif

  if(strcmp(function, "register") == 0) {
    char f = 'r';
    send(sock, &f, sizeof(char), 0);
#ifdef BENCH
    t_start = rdtsc();
#endif
    if(user_registration_c(sock, username, strlen(username), pw, strlen(pw)) != 0) return -1;
#ifdef BENCH
    t_end = rdtsc();
#endif
  }
  else if(strcmp(function, "authentication") == 0) {
    char f = 'a';
    send(sock, &f, sizeof(char), 0);
#ifdef BENCH
    t_start = rdtsc();
#endif
    if(session_c(sock, username, strlen(username), pw, strlen(pw), shared_key) != 0) return -1;
#ifdef BENCH
    t_end = rdtsc();
#endif
    debug_print("Client Shared Key", shared_key, SHARED_KEY_LEN);
  } 
  else {
    printf("Wrong function: %s\n", function);
    return -1;
  }
  
#ifdef BENCH
  printf("%s took %lu cycles\n", function, t_end - t_start);
#endif

  return 0;    
}
