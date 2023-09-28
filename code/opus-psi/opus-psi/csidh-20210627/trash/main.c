
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "fp.h"
#include "csidh.h"

void uint_print(uint const *x)
{
    for (size_t i = 8*LIMBS-1; i < 8*LIMBS; --i)
        printf("%02hhx", i[(unsigned char *) x->c]);
}

void priv_print(private_key const *k)
{
    char cc = '0';
    for (size_t i = 0; i < sizeof(k->e)/sizeof(*k->e); ++i) {
        char nc = k->e[i] > 0 ? '6' : k->e[i] < 0 ? '4' : '7';
        if (nc != cc) cc = nc, printf("\x1b[3%cm", cc);
        printf(MAX_EXPONENT < 16 ? "%x" : "%02x", abs(k->e[i]));
    }
    printf("\x1b[0m");
}

int main()
{
    bool ret; (void) ret;
    clock_t t0, t1;

    private_key priv_alice, priv_bob;
    public_key pub_alice, pub_bob;
    public_key shared_alice, shared_bob;

    t0=clock();
    for(size_t i=0; i<100; ++i){
            csidh_private(&priv_alice);
            ret = csidh(&pub_alice, &base, &priv_alice);
            fp invertible; 
            fp_enc(&invertible, &pub_alice.A);
            fp_inv(&invertible);
            fp_dec(&pub_alice.A,&invertible);
            if(!validate_basic(pub_alice)){
                    printf("fail at run %d\n", i);
                    return -1;
            }
            printf("finished with %d\n", i);
    }
    t1=clock();
    printf("%f elapsed\n", (double)(t1-t0)/CLOCKS_PER_SEC);

    return 0; 
}

