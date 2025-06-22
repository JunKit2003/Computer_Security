#include <stdio.h>
#include <openssl/bn.h>

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    // Set values
    BN_dec2bn(&p, "37");
    BN_dec2bn(&q, "67");
    BN_dec2bn(&e, "169");
    BN_dec2bn(&C, "1744");

    // n = p * q
    BN_mul(n, p, q, ctx);

    // phi = (p - 1)(q - 1)
    BN_sub(temp1, p, BN_value_one());
    BN_sub(temp2, q, BN_value_one());
    BN_mul(phi, temp1, temp2, ctx);

    // d = e^-1 mod phi
    BN_mod_inverse(d, e, phi, ctx);

    // M = C^d mod n
    BN_mod_exp(M, C, d, n, ctx);

    // Print results
    char *n_str = BN_bn2dec(n);
    char *phi_str = BN_bn2dec(phi);
    char *d_str = BN_bn2dec(d);
    char *M_str = BN_bn2dec(M);

    printf("n (modulus)      : %s\n", n_str);
    printf("phi(n)           : %s\n", phi_str);
    printf("Decryption key d : %s\n", d_str);
    printf("Decrypted M      : %s\n", M_str);

    // Free memory
    OPENSSL_free(n_str);
    OPENSSL_free(phi_str);
    OPENSSL_free(d_str);
    OPENSSL_free(M_str);

    BN_free(p); BN_free(q); BN_free(n); BN_free(phi); BN_free(e); BN_free(d);
    BN_free(C); BN_free(M); BN_free(temp1); BN_free(temp2);
    BN_CTX_free(ctx);

    return 0;
}