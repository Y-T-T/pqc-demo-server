#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <crypto/deprecated/rsa_pkcs1_sha384.h>
#include <crypto/openssl_base.h>

static void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

uchar * sign_msg(const uchar *msg, const uint32_t msg_len, uint32_t *outlen){
    
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    uchar *sig = NULL;
    FILE *keyfile;
    RSA *rsa = NULL;

    keyfile = fopen("cert/server.key", "r");
    if (!keyfile) {
        fprintf(stderr, "Unable to open key file\n");
        // return 1;
    }
    rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    if (!rsa) {
        fprintf(stderr, "Unable to read private key\n");
        // return 1;
    }
    
    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        handleErrors();
    }
    sig = malloc(EVP_PKEY_size(pkey) * sizeof(uchar));

    // create ctx
    if(!(mdctx = EVP_MD_CTX_new())) handleErrors();

    // init signature
    if (1 != EVP_SignInit(mdctx, EVP_sha384())) {
        handleErrors();
    }

    // // set pss padding
    // if (1 != EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mdctx), RSA_PKCS1_PSS_PADDING)) {
    //     handleErrors();
    // }

    // // set salt
    // if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(mdctx), -2)) { // -2 meaning same length with hash func
    //     handleErrors();
    // }

    if (1 != EVP_SignUpdate(mdctx, msg, msg_len)) {
        handleErrors();
    }

    // calc signature size
    // if (1 != EVP_DigestSignFinal(mdctx, NULL, &(*outlen))) {
    //     handleErrors();
    // }

    // sig = (uchar *)malloc(*outlen);
    // if (!sig) {
    //     fprintf(stderr, "Unable to allocate memory for signature\n");
    //     // return 1;
    // }

    // calc signature
    if (1 != EVP_SignFinal(mdctx, sig, &(*outlen), pkey)) {
        handleErrors();
    }

    // clear
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return sig;
}

int verify_msg(const uchar *msg, const size_t msg_len, const uchar *sig, const uint32_t siglen){
    
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    FILE *keyfile;
    RSA *rsa = NULL;

    keyfile = fopen("cert/server.pub", "r");
    if (!keyfile) {
        fprintf(stderr, "Unable to open key file\n");
        // return 1;
    }
    rsa = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    if (!rsa) {
        fprintf(stderr, "Unable to read private key\n");
        // return 1;
    }

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        handleErrors();
    }

    // create ctx
    if(!(mdctx = EVP_MD_CTX_new())) handleErrors();

    // init signature
    if (1 != EVP_VerifyInit(mdctx, EVP_sha384())) {
        handleErrors();
    }

    if (1 != EVP_VerifyUpdate(mdctx, msg, msg_len)) {
        handleErrors();
    }

    int verify = EVP_VerifyFinal(mdctx, sig, siglen, pkey);

    // clear
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return verify;
}

// int main(int argc, char const *argv[])
// {
//     const uchar test[] = "test string";
//     uint32_t outlen;

//     uchar *sig = NULL;

//     sig = sign_msg(test, strlen((char *)test), &outlen);

//     print_bytes(sig, outlen);

//     if(verify_msg(test, strlen((char *)test), sig, outlen))
//         printf("Success.\n");

//     free(sig);
//     return 0;
// }

#pragma GCC diagnostic pop