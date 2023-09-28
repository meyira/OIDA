#include "utils.h"
#include "opaque-common.h"

int user_registration_s(int socket, UserDataBase *db) {
  size_t username_len;
  if(read_len(socket, (unsigned char *) &username_len, sizeof(size_t), "username len") != 0) return -1;
  
  char *username = (char *) calloc(username_len + 1, sizeof(char));
  if(!username) return -1;
  if(read_len(socket, (unsigned char *) username, username_len, "username") != 0) goto err;

  if(lookup(db, username)) {
    printf("User exists already\n");
    goto err;
  }
  
  uint8_t blinded[crypto_core_ristretto255_BYTES];
  if(read_len(socket, blinded, sizeof(blinded), "blinded") != 0) goto err;

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(opaque_CreateRegistrationResponse(blinded, 0, sec, pub) != 0) {
    printf("Create Registration Response failed\n");
    goto err;
  }
  send(socket, pub, sizeof(pub), 0);

  uint8_t reg_record[OPAQUE_REGISTRATION_RECORD_LEN];
  if(read_len(socket, reg_record, sizeof(reg_record), "register record") != 0) goto err;

  User new_user;
  new_user.username = username;
  opaque_StoreUserRecord(sec, reg_record, new_user.user_record);
  add_user(db, &new_user);
  return 0;

err:
  if(!username) free(username);
  return -1;
}

int session_s(int socket, UserDataBase *db, unsigned char *shared_key) {
  size_t username_len;
  if(read_len(socket, (unsigned char *) &username_len, sizeof(size_t), "username len") != 0) return -1;

  char *username = (char *) calloc(username_len + 1, sizeof(char));
  if(!username) return -1;
  if(read_len(socket, (unsigned char *) username, username_len, "username") != 0) goto err;

  User *user;
  if(!(user = lookup(db, username))) {
    printf("User %s does not exist\n", username);
    goto err;
  }

  uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t auth_server[crypto_auth_hmacsha512_BYTES];
  const Opaque_Ids ids = {4, (uint8_t *) "user", 6, (uint8_t *) "server"};
  if(read_len(socket, pub, sizeof(pub), "pub") != 0) goto err;
  if(opaque_CreateCredentialResponse(pub, user->user_record, &ids, (const uint8_t *) "OPAQUE", 6, resp, shared_key, auth_server) != 0) {
    printf("Create Credential Response failed\n");
    goto err;
  }

  send(socket, resp, sizeof(resp), 0);

  uint8_t auth_client[crypto_auth_hmacsha512_BYTES];
  if(read_len(socket, auth_client, sizeof(auth_client), "auth client") != 0) goto err;
  if(opaque_UserAuth(auth_server, auth_client) != 0) {
    printf("User Authentication failed\n");
    goto err;
  }

  free(username);
  return 0;

err:
  if(!username) free(username);
  return -1;
}

int main(int argc, char *argv[]) {
#ifdef BENCH
  // Unbuffered stdout required for bench python script
  setvbuf(stdout, 0, _IONBF, 0);
#endif
  if(argc != 2){
    printf("Usage: ./opaque-server [PORT]\n"); 
    return -1; 
  }

  int sock, serversocket;
  uint16_t port = htons(atoll(argv[1])); 
  struct sockaddr other;
  socklen_t otherlen = sizeof(struct sockaddr);
  if(setup_socket_s(&serversocket, port) != 0) return -1;

  unsigned char shared_key[OPAQUE_SHARED_SECRETBYTES];
  UserDataBase db = {0};
  if(init_list(&db, 10) != 0) return -1;
  
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
      debug_print("Server Shared Key", shared_key, OPAQUE_SHARED_SECRETBYTES);
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
