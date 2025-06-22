#include <stdio.h>
#include <openssl/bn.h>

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *xa = BN_new();
    BIGNUM *xb = BN_new();
    BIGNUM *ya = BN_new();
    BIGNUM *yb = BN_new();
    BIGNUM *kab1 = BN_new();
    BIGNUM *kab2 = BN_new();

    // Set values
    BN_dec2bn(&p, "773");
    BN_dec2bn(&g, "200");
    BN_dec2bn(&xa, "333");
    BN_dec2bn(&xb, "603");

    // y_a = g^x_a mod p
    BN_mod_exp(ya, g, xa, p, ctx);

    // y_b = g^x_b mod p
    BN_mod_exp(yb, g, xb, p, ctx);

    // K_ab = y_b^x_a mod p
    BN_mod_exp(kab1, yb, xa, p, ctx);

    // (Optional: K_ab from other side to double-check)
    BN_mod_exp(kab2, ya, xb, p, ctx);

    // Print results
    char *ya_str = BN_bn2dec(ya);
    char *yb_str = BN_bn2dec(yb);
    char *kab_str = BN_bn2dec(kab1);
    char *kab2_str = BN_bn2dec(kab2);

    printf("Alice's public key (y_a): %s\n", ya_str);
    printf("Bob's public key (y_b): %s\n", yb_str);
    printf("Shared secret key (K_ab): %s\n", kab_str);
    printf("Verification (K_ab from other side): %s\n", kab2_str);

    // Cleanup
    OPENSSL_free(ya_str);
    OPENSSL_free(yb_str);
    OPENSSL_free(kab_str);
    OPENSSL_free(kab2_str);
    BN_free(p); BN_free(g); BN_free(xa); BN_free(xb);
    BN_free(ya); BN_free(yb); BN_free(kab1); BN_free(kab2);
    BN_CTX_free(ctx);

    return 0;
}