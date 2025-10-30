#include <gmp.h>
#include <stdio.h>

int main(void) {
    mpz_t p, g, a, b, A, B, s1, s2;
    mpz_inits(p, g, a, b, A, B, s1, s2, NULL);

    mpz_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16);
    mpz_set_ui(g, 5);

    mpz_set_ui(a, 12345);
    mpz_set_ui(b, 67890);

    mpz_powm(A, g, a, p);
    mpz_powm(B, g, b, p);

    mpz_powm(s1, B, a, p);
    mpz_powm(s2, A, b, p);

    gmp_printf("Shared secret: 0x%Zx\n", s1);
    mpz_clears(p, g, a, b, A, B, s1, s2, NULL);
}
