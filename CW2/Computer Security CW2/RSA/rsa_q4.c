#include <stdio.h>
#include <openssl/bn.h>

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *S = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M_verify = BN_new();

    // Set known values
    BN_dec2bn(&S, "1459");
    BN_dec2bn(&n, "2479");
    BN_dec2bn(&e, "169");

    // Compute M' = S^e mod n
    BN_mod_exp(M_verify, S, e, n, ctx);

    // Print result
    char *M_str = BN_bn2dec(M_verify);
    printf("Verified Message from Signature: %s\n", M_str);

    // Free
    OPENSSL_free(M_str);
    BN_free(S); BN_free(n); BN_free(e); BN_free(M_verify);
    BN_CTX_free(ctx);

    return 0;
}