#include <stdio.h>
#include <openssl/bn.h>

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *xb = BN_new();     // Bob's private key
    BIGNUM *C1 = BN_new();
    BIGNUM *C2 = BN_new();
    BIGNUM *K = BN_new();      // Shared key
    BIGNUM *Kinv = BN_new();   // Inverse of K
    BIGNUM *M = BN_new();      // Decrypted message
    BIGNUM *temp = BN_new();

    // Set values from question
    BN_dec2bn(&p, "6469");
    BN_dec2bn(&xb, "4127");
    BN_dec2bn(&C1, "3533");
    BN_dec2bn(&C2, "3719");

    // K = C1^x_b mod p
    BN_mod_exp(K, C1, xb, p, ctx);

    // K^-1 mod p
    BN_mod_inverse(Kinv, K, p, ctx);

    // M = (C2 * K^-1) mod p
    BN_mul(temp, C2, Kinv, ctx);
    BN_mod(M, temp, p, ctx);

    // Output
    char *K_str = BN_bn2dec(K);
    char *Kinv_str = BN_bn2dec(Kinv);
    char *M_str = BN_bn2dec(M);

    printf("Recovered shared key (K): %s\n", K_str);
    printf("Inverse of shared key (K^-1): %s\n", Kinv_str);
    printf("Decrypted Message (M): %s\n", M_str);

    // Cleanup
    OPENSSL_free(K_str);
    OPENSSL_free(Kinv_str);
    OPENSSL_free(M_str);
    BN_free(p); BN_free(xb); BN_free(C1); BN_free(C2);
    BN_free(K); BN_free(Kinv); BN_free(M); BN_free(temp);
    BN_CTX_free(ctx);

    return 0;
}
