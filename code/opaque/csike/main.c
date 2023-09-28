#include <stdio.h>
#include "csike.h"

int main(void) {
   public_key pk;
   CSIKESecretKeyPair sk;
   csike_keygen(&pk, &sk);

   uint8_t c[CSIDH_PK_LEN + NUM_BYTES];
   uint8_t tau[NUM_BYTES];
   uint8_t ks[NUM_BYTES];
   csike_encap(&pk, c, ks, tau);

   uint8_t ks2[NUM_BYTES];
   csike_decap(c, tau, &sk, ks2);

   if(memcmp(ks, ks2, NUM_BYTES) != 0) {
    printf("keys do not match");
   }

   return 0;
}