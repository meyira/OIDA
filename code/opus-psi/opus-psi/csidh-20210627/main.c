
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "fp.h"
#include "fp2.h"
#include "csidh.h"


int main()
{
    bool ret; (void) ret;
    clock_t t0, t1;

    private_key priv_alice, priv_bob;
    public_key pub_alice, pub_bob;
    public_key shared_alice, shared_bob;

    t0=clock();
    csidh_private(&priv_alice);
    ret = csidh(&pub_alice, &base, &priv_alice);
    fp invertible; 
    fp_enc(&invertible, &pub_alice.A);
    fp_inv(&invertible);
    fp_dec(&pub_alice.A,&invertible);
    if(!validate_basic(&pub_alice)){
            printf("fail");
            return -1;
    }
    t1=clock();
    for(size_t i=0;i<NUM_PRIMES; ++i)
            priv_alice.e[i]=-priv_alice.e[i];
    ret = csidh(&pub_bob, &base, &priv_alice);
    if(!validate_basic(&pub_bob)){
            printf("fail");
            return -1;
    }

    uint_print(&pub_alice.A);
    uint_print(&pub_bob.A);
    printf("%f elapsed\n", (double)(t1-t0)/CLOCKS_PER_SEC);

    return 0; 
}

