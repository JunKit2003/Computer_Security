#include <stdio.h>
#include <openssl/bn.h>

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    // Set known values
    BN_dec2bn(&p, "223");
    BN_dec2bn(&q, "311");
    BN_dec2bn(&n, "69353");
    BN_dec2bn(&d, "29401");
    BN_dec2bn(&M, "12345");

    // phi = (p - 1) * (q - 1)
    BN_sub(temp1, p, BN_value_one()); // temp1 = p - 1
    BN_sub(temp2, q, BN_value_one()); // temp2 = q - 1
    BN_mul(phi, temp1, temp2, ctx);   // phi = (p-1)(q-1)

    // e = d^-1 mod phi
    BN_mod_inverse(e, d, phi, ctx);

    // Encrypt C = M^e mod n
    BN_mod_exp(C, M, e, n, ctx);

    // Print results
    char *e_str = BN_bn2dec(e);
    char *C_str = BN_bn2dec(C);

    printf("Encryption key e: %s\n", e_str);
    printf("Ciphertext C: %s\n", C_str);

    // Free memory
    OPENSSL_free(e_str);
    OPENSSL_free(C_str);

    BN_free(p); BN_free(q); BN_free(n); BN_free(phi); BN_free(e); BN_free(d);
    BN_free(M); BN_free(C); BN_free(temp1); BN_free(temp2);
    BN_CTX_free(ctx);

    return 0;
}