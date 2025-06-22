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
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    // Set values
    BN_dec2bn(&p, "71");
    BN_dec2bn(&q, "97");
    BN_dec2bn(&n, "6887");
    BN_dec2bn(&e, "143");
    BN_dec2bn(&M, "1234");

    // phi = (p-1)(q-1)
    BN_sub(temp1, p, BN_value_one()); // temp1 = p - 1
    BN_sub(temp2, q, BN_value_one()); // temp2 = q - 1
    BN_mul(phi, temp1, temp2, ctx);   // phi = (p-1)(q-1)

    // Compute d = e^-1 mod phi
    BN_mod_inverse(d, e, phi, ctx);

    // Compute C = M^e mod n
    BN_mod_exp(C, M, e, n, ctx);

    // Print results
    char *d_str = BN_bn2dec(d);
    char *C_str = BN_bn2dec(C);

    printf("Decryption key d: %s\n", d_str);
    printf("Ciphertext C: %s\n", C_str);

    // Free
    OPENSSL_free(d_str);
    OPENSSL_free(C_str);

    BN_free(p); BN_free(q); BN_free(n); BN_free(phi); BN_free(e); BN_free(d);
    BN_free(M); BN_free(C); BN_free(temp1); BN_free(temp2);
    BN_CTX_free(ctx);

    return 0;
}
