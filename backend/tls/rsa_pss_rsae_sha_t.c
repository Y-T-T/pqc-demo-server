#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <tls/rsa_pss_rsae_sha_t.h>

static void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

static void print_public_key(RSA *rsa) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa)) {
        fprintf(stderr, "Error writing public key to buffer\n");
        return;
    }

    char *key_data;
    long key_len = BIO_get_mem_data(bio, &key_data);

    printf("Public Key:\n%.*s\n", (int)key_len, key_data);

    BIO_free(bio);
}

u8 * sign_msg(const u8 *msg, const uint32_t msg_len, const EVP_MD *alg, size_t *siglen){
    
    EVP_PKEY_CTX *pctx;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *pkey = NULL;
    u8 *sig = NULL;
    FILE *keyfile;
    // RSA *rsa = NULL;

    // keyfile = fopen("cert/server.key", "rb");
    keyfile = fopen("../src/cert/www.pqc-demo.xyz.key", "rb");
    if (!keyfile) {
        fprintf(stderr, "Unable to open key file\n");
        // return 1;
    }
    pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    if (!pkey) {
        fprintf(stderr, "Unable to read private key\n");
        // return 1;
    }
    // RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    // if (rsa != NULL) {
    //     BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    //     RSA_print(out, rsa, 0);
    //     BIO_free(out);
    //     RSA_free(rsa);
    // } else {
    //     // handleErrors();
    // }

    // pkey = EVP_PKEY_new();
    // if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    //     handleErrors();
    // }

    // create ctx
    if(!(mdctx = EVP_MD_CTX_new())) handleErrors();

    // init signature
    if (1 != EVP_DigestSignInit(mdctx, &pctx, alg, NULL, pkey)) {
        handleErrors();
    }

    // set pss padding
    if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)) {
        handleErrors();
    }

    // set salt
    if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1)) { // -1 meaning same length with hash func
        handleErrors();
    }

    if (1 != EVP_DigestSignUpdate(mdctx, msg, msg_len)) {
        handleErrors();
    }

    // calc signature size
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &(*siglen))) {
        handleErrors();
    }

    sig = OPENSSL_malloc(*siglen);
    if (!sig) {
        fprintf(stderr, "Unable to allocate memory for signature\n");
        // return 1;
    }

    // calc signature
    if (1 != EVP_DigestSignFinal(mdctx, sig, &(*siglen))) {
        handleErrors();
    }    

    // clear
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return sig;
}

int verify_msg(const u8 *msg, const size_t msg_len, const EVP_MD *alg, const u8 *sig, const size_t siglen){
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx;
    EVP_MD_CTX *mdctx = NULL;
    FILE *keyfile;
    RSA *rsa = NULL;

    // keyfile = fopen("cert/server.key", "rb");
    keyfile = fopen("../src/cert/www.pqc-demo.xyz.key", "rb");
    if (!keyfile) {
        fprintf(stderr, "Unable to open key file\n");
        // return 1;
    }
    pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    rsa = EVP_PKEY_get1_RSA(pkey);
    // rsa = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    if (!rsa) {
        fprintf(stderr, "Unable to read private key\n");
        // return 1;
    }

    // RSA* rsa_pubkey = RSAPublicKey_dup(rsa);
    // if (!rsa_pubkey) {
    //     fprintf(stderr, "Error extracting public key\n");
    //     RSA_free(rsa);
    //     EVP_PKEY_free(pkey);
    //     // exit(1);
    // }
    // print_public_key(rsa_pubkey);

    EVP_PKEY_free(pkey);
    pkey = NULL;

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        handleErrors();
    }

    // create ctx
    if(!(mdctx = EVP_MD_CTX_new())) handleErrors();

    // init signature
    if (1 != EVP_DigestVerifyInit(mdctx, &pctx, alg, NULL, pkey)) {
        handleErrors();
    }

    // set pss padding
    if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)) {
        handleErrors();
    }

    // set salt
    if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1)) { // -1 meaning same length with hash func
        handleErrors();
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, msg, msg_len)) {
        handleErrors();
    }

    int verify = EVP_DigestVerifyFinal(mdctx, sig, siglen);

    // clear
    EVP_MD_CTX_free(mdctx);
    // EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return verify;
}

// int main(int argc, char const *argv[])
// {
//     u8 *msg = NULL;
//     uint64_t msg_len;
//     size_t sig_len;

//     read_file(&msg, &msg_len, "cert/msg", 0);

//     // print_bytes(msg, msg_len);

//     u8 *sig = NULL;

//     sig = sign_msg(msg, msg_len, SHA256, &sig_len);

//     print_bytes(sig, sig_len);

//     if(verify_msg(msg, msg_len, SHA256, sig, sig_len))
//         printf("Verification success.\n");
//     free(msg);
//     OPENSSL_free(sig);
//     return 0;
// }


#pragma GCC diagnostic pop