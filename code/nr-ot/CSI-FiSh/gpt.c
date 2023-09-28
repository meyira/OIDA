#include <stdio.h>
#include <stdint.h>
#include <gmp.h>

// Function to subtract two int8_t arrays using GMP library
void subtract_int8_arrays(int8_t* result, const int8_t* a, const int8_t* b, size_t size) {
    mpz_t mpz_a[size], mpz_b[size], mpz_result[size];

    // Initialize mpz_t arrays
    for (size_t i = 0; i < size; i++) {
        mpz_init(mpz_a[i]);
        mpz_init(mpz_b[i]);
        mpz_init(mpz_result[i]);
    }

    // Convert int8_t arrays to mpz_t
    for (size_t i = 0; i < size; i++) {
        mpz_set_si(mpz_a[i], a[i]);
        mpz_set_si(mpz_b[i], b[i]);
    }

    // Subtract a and b, store result in mpz_result
    for (size_t i = 0; i < size; i++) {
        mpz_sub(mpz_result[i], mpz_a[i], mpz_b[i]);
    }

    // Export result to int8_t array
    for (size_t i = 0; i < size; i++) {
        long int val = mpz_get_si(mpz_result[i]);
        result[i] = (int8_t)val;
    }

    // Clear mpz_t variables
    for (size_t i = 0; i < size; i++) {
        mpz_clear(mpz_a[i]);
        mpz_clear(mpz_b[i]);
        mpz_clear(mpz_result[i]);
    }
}

int main() {
    // Example input arrays
    int8_t a[] = { 5, -3, 7, -1 };
    int8_t b[] = { 2, 1, -6, 0 };
    size_t size = sizeof(a) / sizeof(a[0]);

    // Result array
    int8_t result[size];

    // Subtract a and b
    subtract_int8_arrays(result, a, b, size);

    // Print result
    printf("Result: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", result[i]);
    }
    printf("\n");

    return 0;
}

