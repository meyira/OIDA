#ifndef OPUS_H
#define OPUS_H

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h>

#include "csidh.h"
#include "opaque-common.h"

#ifdef TLS_OPAQUE
#include "openssl/ssl.h"
#endif

void check_oprf(const unsigned char *in, size_t in_len, const private_key *oprf_keys);
int opus_s(int socket, const private_key *oprf_keys, size_t in_len);
int opus_c(int socket, const unsigned char *in, size_t in_len, public_key *out);

#endif
