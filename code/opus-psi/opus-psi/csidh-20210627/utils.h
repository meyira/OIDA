#include <string.h>
#include "csidh.h"


typedef struct pk_res{
  uint32_t id; 
  uint32_t seq; 
  public_key E0;
  public_key E1;
}pk_res;


typedef struct pk_req{
  uint32_t id; 
  uint32_t seq; 
  public_key E;
}pk_req;


