#include "utils.h"

int init_list(UserDataBase *db, size_t size) {
  if(!db) return -1;

  if(db->users) {
    printf("List already initialized\n");
    return -1;
  }

  db->users = calloc(size, sizeof(User));
  if(!db->users) {
    printf("Calloc failed\n");
    return -1;
  }
  db->size = size;
  db->indx = 0;

  return 0;
}

int add_user(UserDataBase *db, User *to_add) {
  if(!db || !to_add) return -1;

  if(db->indx == db->size) {
    size_t new_size = 0;
    if(__builtin_mul_overflow(db->size, 2, &new_size)) {
      printf("Overflow\n");
      return -1;
    }

    User *temp = realloc(db->users, new_size * sizeof(User));
    if(!temp) {
      printf("Realloc failed\n");
      return -1;
    }

    db->users = temp;
    memset(db->users + db->size, 0, db->size);
    db->size = new_size;
  }

  memcpy(&db->users[db->indx++], to_add, sizeof(User));
  return 0;
}

User *lookup(const UserDataBase *db, const char *username) {
  if(!db || !username) return 0;
  User *user = 0;

  for(size_t i = 0; i < db->indx; i++) {
    if(strcmp(db->users[i].username, username) == 0) {
      user = &db->users[i];
      break;
    }
  }

  return user;
}

void destroy_list(UserDataBase *db) {
  if(!db) return;

  for(size_t i = 0; i < db->indx; i++) {
    User *curr_user = &db->users[i];
    free(curr_user->username);
    memset(curr_user, 0, sizeof(User));
  }
  
  free(db->users);
  db->users = 0;
  db->size = 0;
  db->indx = 0;
}
