#include "fp2.h"
#include "fp.h"

static void fp_pow(fp *x, limbs const *e)
{
    fp y = *x;
    *x = fp_1;
    for (size_t k = 0; k < LIMBS; ++k) {
        uint64_t t = e->c[k];
        for (size_t i = 0; i < 64; ++i, t >>= 1) {
            if (t & 1)
                fp_mul2(x, &y);
            fp_sq1(&y);
        }
    }
}


__attribute__((visibility("default")))
void fp_enc(fp *x, limbs const *y)
{
    fp_mul3(x, (fp *) y, &r_squared_mod_p);
}

__attribute__((visibility("default")))
void fp_dec(limbs *x, fp const *y)
{
    fp_mul3((fp *) x, y, (fp *) &uint_1);
}
__attribute__((visibility("default")))
void fp_inv(fp *x)
{
    fp_pow(x, &p_minus_2);
}
