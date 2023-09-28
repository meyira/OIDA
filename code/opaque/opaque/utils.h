#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aux_/crypto_kdf_hkdf_sha512.h"
#include "common.h"
#include "opaque.h"

typedef struct User {
  char *username;
  uint8_t user_record[OPAQUE_USER_RECORD_LEN];
} User;

typedef struct UserDataBase {
  User *users;
  size_t size;
  size_t indx;
} UserDataBase;

//TODO: UserDataBase, maybe move these functions into opaque_common
//TODO: update pq-utils in paper repo
int init_list(UserDataBase *db, size_t size);
int add_user(UserDataBase *db, User *to_add);
User *lookup(const UserDataBase *db, const char *username);
void destroy_list(UserDataBase *db);

#endif
