#include "utils.h"
#include "opaque-common.h"

int user_registration_c(int socket, const char *username, size_t username_len, const unsigned char *pw, size_t pw_len) {
  // Send username len + username (without 0 byte)
  send(socket, &username_len, sizeof(size_t), 0);
  send(socket, username, username_len, 0); 

  uint8_t *sec = (uint8_t *) calloc(sizeof(uint8_t), OPAQUE_REGISTER_USER_SEC_LEN + pw_len);
  if(!sec) goto err;
  uint8_t blinded[crypto_core_ristretto255_BYTES];
  if(opaque_CreateRegistrationRequest(pw, pw_len, sec, blinded) != 0) {
    printf("Create Registration Request failed\n");
    goto err;
  }
  
  send(socket, blinded, sizeof(blinded), 0);

  uint8_t response[OPAQUE_REGISTER_PUBLIC_LEN];
  uint8_t record[OPAQUE_REGISTRATION_RECORD_LEN];
  if(read_len(socket, response, sizeof(response), "registration response") != 0) goto err;
  const Opaque_Ids ids = {4, (uint8_t *) "user", 6, (uint8_t *) "server"};
  if(opaque_FinalizeRequest(sec, response, &ids, record, 0) != 0) {
    printf("Finalize Request failed\n");
    goto err;
  }

  send(socket, record, sizeof(record), 0); 
  free(sec);
  return 0;

err:
  if(!sec) free(sec);
  return -1;
}

int session_c(int socket, const char *username, size_t username_len, const unsigned char *pw, size_t pw_len, unsigned char *shared_key) {
  //Send username len + username (without 0 byte)
  send(socket, &username_len, sizeof(size_t), 0);
  send(socket, username, username_len, 0);

  uint8_t *sec = (uint8_t *) calloc(sizeof(uint8_t), OPAQUE_USER_SESSION_SECRET_LEN + pw_len);
  if(!sec) goto err;
  uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  if(opaque_CreateCredentialRequest(pw, pw_len, sec, pub) != 0) {
    printf("Create Credential Request failed\n");
    goto err;
  }

  send(socket, pub, sizeof(pub), 0);

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t auth_client[crypto_auth_hmacsha512_BYTES];
  const Opaque_Ids ids = {4, (uint8_t *) "user", 6, (uint8_t *) "server"};
  if(read_len(socket, resp, sizeof(resp), "resp") != 0) goto err;
  if(opaque_RecoverCredentials(resp, sec, (uint8_t *) "OPAQUE", 6, &ids, shared_key, auth_client, 0) != 0) {
    printf("Recover Credentials failed\n");
    goto err;
  }

  send(socket, auth_client, sizeof(auth_client), 0);

  free(sec);
  return 0;

err:
  if(!sec) free(sec);
  return -1;
}

int main(int argc, char *argv[]) {
  if(argc != 6) {
    printf("Usage: ./opaque-client [IP] [PORT] [username] [password] [register/authentication]\n"); 
    return -1; 
  }
  
  int sock;
  const char *hostname = argv[1];
  uint16_t port = htons(atoi(argv[2]));
  setup_socket_c(&sock, hostname, port);
  
  const char *username = argv[3];
  const unsigned char *pw = (unsigned char *) argv[4];
  const char *function = argv[5];
  unsigned char shared_key[OPAQUE_SHARED_SECRETBYTES];
  
#ifdef BENCH
  uint64_t t_start, t_end;
#endif

  if(strcmp(function, "register") == 0) {
    char f = 'r';
    send(sock, &f, sizeof(char), 0);
#ifdef BENCH
    t_start = rdtsc();
#endif
    if(user_registration_c(sock, username, strlen(username), pw, strlen((const char *) pw)) != 0) return -1;
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
    if(session_c(sock, username, strlen(username), pw, strlen((const char *) pw), shared_key) != 0) return -1;
#ifdef BENCH
    t_end = rdtsc();
#endif
    debug_print("Client Shared Key", shared_key, OPAQUE_SHARED_SECRETBYTES);
  } 
  else {
    printf("Wrong function: %s\n", function);
    return -1;
  }
  
#ifdef BENCH
  printf("%s took %lu cycles\n", function, t_end - t_start);
#endif

  close(sock);
  return 0;    
}
