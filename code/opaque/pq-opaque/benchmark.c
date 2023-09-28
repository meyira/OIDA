#include "utils.h"
#include "opaque-common.h"

int cmp(void *v1, void *v2) {
  return *((uint64_t *) v1) - *((uint64_t *) v2);
}

uint64_t median(uint64_t *diff, size_t iteration_count) {
  qsort(diff, iteration_count, sizeof(uint64_t), (__compar_fn_t) cmp);
  return diff[iteration_count / 2];
}

int main(int argc, char *argv[]) {
  if(argc != 2) {
    printf("Usage: ./benchmark [ITERATION_COUNT]\n");
    return -1;
  }

  size_t iteration_count = atoll(argv[1]);
  uint64_t *diff = (uint64_t *) calloc(iteration_count, sizeof(uint64_t));
  uint64_t sum = 0;
  private_key oprf_keys[NUM_OPRF_KEYS];

  // Bench OPRF without network communication overhead
  printf("Bench OPRF without network communication overhead\n");
  for(size_t i = 0; i < iteration_count; i++) {
    for(size_t j = 0; j < NUM_OPRF_KEYS; j++) {
      csidh_private(&oprf_keys[j]);
    }
    unsigned char in[crypto_hash_sha256_BYTES];
    randombytes_buf(in, sizeof(in));

    uint64_t t_start = rdtsc();
    check_oprf(in, sizeof(in), oprf_keys);
    uint64_t t_end = rdtsc();
    diff[i] = t_end - t_start; 
    sum += (t_end - t_start);
  }
  
  printf("Average cycle count across %ld iterations: %.3lf\n", iteration_count, (double) sum / iteration_count);
  printf("Average cycle time across %ld iterations: %.3lf\n", iteration_count, (double) (sum / iteration_count)/CLOCKS_PER_SEC);
  printf("Median cycle count across %ld iterations: %ld\n", iteration_count, median(diff, iteration_count)/CLOCKS_PER_SEC);
  printf("Median cycle count across %ld iterations: %ld\n", iteration_count, median(diff, iteration_count));
  
  return 0;
}
