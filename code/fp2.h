#include "p512/params.h"
#include "uint.h"
#include "constants.h"

void fp_enc(fp *x, limbs const *y); /* encode to Montgomery representation */
void fp_dec(limbs *x, fp const *y); /* decode from Montgomery representation */
void fp_inv(fp *x);



