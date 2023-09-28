#ifndef NR_OPRF_H
#define NR_OPRF_H

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <gmpxx.h>
#include "pq-ot/pq-ot.h"
#include <cinttypes>

#ifdef __cplusplus
extern "C" {
#endif
#include "fp.h"
#include "csidh.h"
#include "classgroup.h"

  void kat(const unsigned char *seed, const unsigned char *hashed_pw, public_key *out);
  int nr_oprf_c(int socket, const unsigned char *in, size_t in_len, public_key *out);
  int nr_oprf_s(int socket, const unsigned char *seed, size_t in_len);
#ifdef __cplusplus
}
#endif

#endif
