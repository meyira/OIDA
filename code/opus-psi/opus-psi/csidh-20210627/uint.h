#ifndef UINT_H
#define UINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "params.h"

extern const limbs uint_0;
extern const limbs uint_1;

bool uint_eq(limbs const *x, limbs const *y);

void uint_set(limbs *x, uint64_t y);

size_t uint_len(limbs const *x);
bool uint_bit(limbs const *x, uint64_t k);

bool uint_add3(limbs *x, limbs const *y, limbs const *z); /* returns carry */
bool uint_sub3(limbs *x, limbs const *y, limbs const *z); /* returns borrow */

void uint_mul3_64(limbs *x, limbs const *y, uint64_t z);

bool uint_eq(limbs const *x, limbs const *y);

void uint_random(limbs *x, limbs const *m);   /* uniform in the interval [0;m) */

#endif
