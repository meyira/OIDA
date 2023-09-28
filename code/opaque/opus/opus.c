#include "opus.h"

void check_oprf(const unsigned char *in, size_t in_len, const private_key *oprf_keys) {
  public_key server_result;
  large_private_key aggregated = {0};
  add_large_key(&aggregated, &oprf_keys[0]);

  for(size_t i = 0; i < (in_len * 8); i++) {
    if((in[i / 8] >> (i % 8)) & 1) {
      add_large_key(&aggregated, &oprf_keys[i + 1]);
    }
  }
  large_csidh(&server_result, &base, &aggregated);
#ifdef DEBUG
  uint_print(&server_result.A);
#endif
}

int opus_s(int socket, const private_key *oprf_keys, size_t in_len) {
  private_key rs;
  public_key s_E_0, s_E_1, client_result;
  large_private_key unblind = {0};
  for(size_t i = 0; i < in_len * 8; i++) {
    csidh_private(&rs);
    sub_large_key(&unblind, &rs);
    if(read_len(socket, (unsigned char *) &client_result, sizeof(public_key), "client result") == -1) return -1;

    if(csidh(&s_E_0, &client_result, &rs) != true) return -1;
    if(csidh(&s_E_1, &s_E_0, &oprf_keys[i + 1]) != true) return -1;
    send(socket, &s_E_0, sizeof(public_key), 0);
    send(socket, &s_E_1, sizeof(public_key), 0);
  }

  if(read_len(socket, (unsigned char *) &client_result, sizeof(public_key), "client result") == -1) return -1;
  add_large_key(&unblind, &oprf_keys[0]);
  if(large_csidh(&client_result, &client_result, &unblind) != true) return -1;
  send(socket, &client_result, sizeof(public_key), 0);
  return 0;
}

int opus_c(int socket, const unsigned char *in, size_t in_len, public_key *out) {
  private_key blinder;
  public_key client_result = {0};
  public_key s_E_0, s_E_1;
  large_private_key unblind = {0};
  for(size_t i = 0; i < in_len * 8; i++) {
    csidh_private(&blinder);
    sub_large_key(&unblind, &blinder);
    if(csidh(&client_result, &client_result, &blinder) != true) return -1;
    send(socket, &client_result, sizeof(public_key), 0);
    if(read_len(socket, (unsigned char *) &s_E_0, sizeof(public_key), "s_E_0") == -1) return -1;
    if(read_len(socket, (unsigned char *) &s_E_1, sizeof(public_key), "s_E_1") == -1) return -1;
    
    if((in[i / 8] >> (i % 8)) & 1) {
      memcpy(&client_result, &s_E_1, sizeof(public_key));
    }
    else {
      memcpy(&client_result, &s_E_0, sizeof(public_key));
    }
  }

  private_key rc;
  csidh_private(&rc);
  sub_large_key(&unblind, &rc);
  if(csidh(&client_result, &client_result, &rc) != true) return -1;

  send(socket, &client_result, sizeof(public_key), 0);
  if(read_len(socket, (unsigned char *) &client_result, sizeof(public_key), "client result") == -1) return -1;
  if(large_csidh(&client_result, &client_result, &unblind) != true) return -1;
  memcpy(out, &client_result, sizeof(public_key));
  
  return 0;
}
