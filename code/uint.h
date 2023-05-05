#ifndef UINT_H
#define UINT_H

#include <stdbool.h>
#include <stdint.h>

#include "params.h"

extern const uint_s uint_0;
extern const uint_s uint_1;

bool uint_eq(uint_s const *x, uint_s const *y);

void uint_set(uint_s *x, uint64_t y);

size_t uint_len(uint_s const *x);
bool uint_bit(uint_s const *x, uint64_t k);

bool uint_add3(uint_s *x, uint_s const *y, uint_s const *z); /* returns carry */
bool uint_sub3(uint_s *x, uint_s const *y, uint_s const *z); /* returns borrow */

void uint_mul3_64(uint_s *x, uint_s const *y, uint64_t z);

bool uint_eq(uint_s const *x, uint_s const *y);

void uint_random(uint_s *x, uint_s const *m);   /* uniform in the interval [0;m) */

#endif
