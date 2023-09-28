#ifndef UINT_H
#define UINT_H

#include <stdbool.h>
#include <stdint.h>

#include "p512/params.h"

extern const uint_s uint_1;

void uint_set(uint_s *x, uint64_t y);

bool uint_bit(uint_s const *x, uint64_t k);

bool uint_add3(uint_s *x, uint_s const *y, uint_s const *z); /* returns carry */
bool uint_sub3(uint_s *x, uint_s const *y, uint_s const *z); /* returns borrow */

void uint_mul3_64(uint_s *x, uint_s const *y, uint64_t z);

#endif
