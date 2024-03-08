#include <base/param.h>
#include <server/serving.h>
#include <crypto/aes_256_gcm.h>
#include <crypto/x25519.h>
#include <tls/tls13_hkdf_expand.h>
#include <tls/rsa_pss_rsae_sha_t.h>
#include <kyber/kem.h>

#define PORT 443
#define SERVER_ADDR "127.0.0.1"

int proxy_sock, client_sock, server_sock;
struct sockaddr_in proxy_addr, client_addr, server_addr;

void sigint_handler(int sig){
    printf("\nClosing proxy socket...");
    close(proxy_sock);
    printf("Done.\nExit.\n");
    // exit(0);
}

void loadProxySetting(){
    int yes = 1;
    if(setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) error("Error on setsockopt.\n");
}

void loadTimeoutSetting(int sockfd){
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) == -1) error("Error on setsockopt.\n");
}

void createProxySocket(){
    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    loadProxySetting();
    if (proxy_sock < 0) error("ERROR creating proxy socket.\n");
    else printf("Proxy socket created.\n");

    memset((char *)&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy_addr.sin_port = htons(PORT);

    if (bind(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) error("ERROR on binding.\n");
    else printf("Proxy socket bind on port %d.\n", PORT);

    if (listen(proxy_sock, 10) < 0) error("Listen failed");
    else printf("Listening on port %d...\n", PORT);
}

void parse_client_hello(uchar *client_hello, ssize_t len, uchar *session_id, uchar *X25519_client_pk, uchar *Kyber768_pk){
    int i = 0, j = 0, length;

    // Record Header
    length = 5;
    j += length;
    i += length;
    // printf("Record Header: ");
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Handshake Header
    length = 4;
    j += length;
    i += length;
    // printf("Handshake Header: ");
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Client Version
    length = 2;
    j += length;
    i += length;
    // printf("Client Version: ");
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Client Random
    length = 32;
    j += length;
    i += length;
    // printf("Client Random: ");
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Session ID
    length = 33;
    memcpy(session_id, &client_hello[i], length);
    j += length;
    i += length;
    // printf("Session ID: ");
    // print_bytes(session_id, length);

    // Cipher Suites
    length = client_hello[i] << 8 | client_hello[i+1];
    j += length + 2;
    i += length + 2;
    // printf("Cipher Suites(length = %d): ", length);
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Compression Methods
    length = 2;
    j += length;
    i += length;
    // printf("Compression Methods: ");
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Extensions Length
    length = 2;
    j += length;
    i += length;
    // printf("Extensions Length: ");
    // for(; i < j; i++)
    //     printf("%02x ", client_hello[i]);
    // printf("\n");

    // Find key_share extension
    while(!(client_hello[i] == 0x00 && client_hello[i+1] == 0x33)){
        length = client_hello[i+2] << 8 | client_hello[i+3];
        i += length + 4;
    }
    // printf("Find: %02x %02x\n", client_hello[i], client_hello[i+1]);

    // key_share
    length = client_hello[i+2] << 8 | client_hello[i+3];
    j = i + 4 + length;
    // printf("i: %d, j: %d\n", i, j);
    // printf("key_share(length:%d):\n", length);
    // for(int z = i; z < j; z++)
    //     printf("%02x", client_hello[z]);
    // printf("\n\n");

    i += 6;
    // Find X25519Kyber768Draft00 public key
    while(!(client_hello[i] == 0x63 && client_hello[i+1] == 0x99)){
        length = client_hello[i+2] << 8 | client_hello[i+3];
        i += length + 4;
    }

    length = client_hello[i+2] << 8 | client_hello[i+3];
    j = i + 4 + length;
    // printf("X25519Kyber768Draft00(length:%d):\n", length);
    // for(int z = i; z < j; z++)
    //     printf("%02x", client_hello[z]);
    // printf("\n\n");

    memcpy(X25519_client_pk, &client_hello[i+4], 32);
    memcpy(Kyber768_pk, &client_hello[i+4+32], 1184);

}

void get_random(uchar *random){
    int fd;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        return;
    }
    if (read(fd, random, 32) != 32) {
        perror("Failed to read random data");
        close(fd);
        return;
    }
    close(fd);
}

void load_certificates(char *filepath, uchar **crt, uint32_t *len){
    // FILE *file = fopen("cert/server.der", "rb");
    // FILE *file = fopen("cert/localhost.der", "rb");
    // FILE *file = fopen("cert/pqc-demo.der", "rb");
    // FILE *file = fopen("cert/test_0.der", "rb");
    FILE *file = fopen(filepath, "rb");
    if (file == NULL)
        printf("Error opening file\n");
    
    fseek(file, 0, SEEK_END);
    *len = ftell(file);
    rewind(file);

    // printf("%d\n", *len);

    uchar *temp = realloc(*crt, (*len) * sizeof(uchar));
    if(temp == NULL)
        fputs("Memory error", stderr);
    else
        *crt = temp;
        fread(*crt, 1, *len, file);
    
    fclose(file);
}

void handshake_key_calc(const uchar *hello_hash, const uchar *ss, uchar **hs, uchar **ssec, uchar **csec, uchar **skey, uchar **ckey, uchar **siv, uchar **civ){
    size_t len = strlen(ZERO_STR) / 2;
    uchar *key = malloc(len * sizeof(uchar));
    uchar *salt = malloc(len * sizeof(uchar));;
    hexStringToBytes(ZERO_STR, key, strlen(ZERO_STR));
    hexStringToBytes(ZERO_STR, salt, strlen(ZERO_STR));

    uchar *early_secret = hkdf_extract(salt, len, key, len);
    // printf("es: ");
    // print_bytes(early_secret, SHA384_DIGEST_LENGTH);
    uchar *empty_hash = sha384(NULL, 0);
    // printf("eh: ");
    // print_bytes(empty_hash, SHA384_DIGEST_LENGTH);

    uchar *derived_secret = derive_secret(early_secret, SHA384_DIGEST_LENGTH, "derived", empty_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    *hs = hkdf_extract(derived_secret, SHA384_DIGEST_LENGTH, ss, SS_LEN);
    *ssec = derive_secret(*hs, SHA384_DIGEST_LENGTH, "s hs traffic", hello_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    *csec = derive_secret(*hs, SHA384_DIGEST_LENGTH, "c hs traffic", hello_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    *skey = derive_secret(*ssec, SHA384_DIGEST_LENGTH, "key", (uchar *)"", 0, AES_KEY_LENGTH_256);
    *ckey = derive_secret(*csec, SHA384_DIGEST_LENGTH, "key", (uchar *)"", 0, AES_KEY_LENGTH_256);
    *siv = derive_secret(*ssec, SHA384_DIGEST_LENGTH, "iv", (uchar *)"", 0, GCM_IV_LENGTH);
    *civ = derive_secret(*csec, SHA384_DIGEST_LENGTH, "iv", (uchar *)"", 0, GCM_IV_LENGTH);

    // printf("ds: ");
    // print_bytes(derived_secret, 48);

    // printf("hs: ");
    // print_bytes(*hs, 48);

    // printf("ssec: ");
    // print_bytes(*ssec, 48);

    // printf("csec: ");
    // print_bytes(*csec, 48);

    // printf("skey: ");
    // print_bytes(*skey, 32);

    // printf("ckey: ");
    // print_bytes(*ckey, 32);

    // printf("siv: ");
    // print_bytes(*siv, 12);

    // printf("civ: ");
    // print_bytes(*civ, 12);

    free(key);
    free(salt);
    free(early_secret);
    free(empty_hash);
    free(derived_secret);
}

void master_key_calc(const uchar *handshake_hash, const uchar *hs, uchar **skey, uchar **siv, uchar **ckey, uchar **civ){
    size_t len = strlen(ZERO_STR) / 2;
    uchar *key = malloc(len * sizeof(uchar));
    hexStringToBytes(ZERO_STR, key, strlen(ZERO_STR));

    uchar *empty_hash = sha384(NULL, 0);
    // printf("eh: ");
    // print_bytes(empty_hash, SHA384_DIGEST_LENGTH);

    uchar *derived_secret = derive_secret(hs, SHA384_DIGEST_LENGTH, "derived", empty_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    uchar *ms = hkdf_extract(derived_secret, SHA384_DIGEST_LENGTH, key, len);
    uchar *ssec = derive_secret(ms, SHA384_DIGEST_LENGTH, "s ap traffic", handshake_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    uchar *csec = derive_secret(ms, SHA384_DIGEST_LENGTH, "c ap traffic", handshake_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    *skey = derive_secret(ssec, SHA384_DIGEST_LENGTH, "key", (uchar *)"", 0, AES_KEY_LENGTH_256);
    *ckey = derive_secret(csec, SHA384_DIGEST_LENGTH, "key", (uchar *)"", 0, AES_KEY_LENGTH_256);
    *siv = derive_secret(ssec, SHA384_DIGEST_LENGTH, "iv", (uchar *)"", 0, GCM_IV_LENGTH);
    *civ = derive_secret(csec, SHA384_DIGEST_LENGTH, "iv", (uchar *)"", 0, GCM_IV_LENGTH);

    free(key);
    free(empty_hash);
    free(derived_secret);
    free(ms);
    free(ssec);
    free(csec);
}

int main() {
    socklen_t client_addr_size = sizeof(client_addr);
    uchar *buffer = malloc(BUFFER_SIZE);
    char client_ip[INET_ADDRSTRLEN];
    ssize_t bytes;
    uint32_t req_len;
    int connectionCount = 0, pool_idx, TLS_handshake_state = 0, len;
    char *testHttpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World!";
    uchar record_header[] = {0x16, 0x03, 0x03, 0x00, 0x00};
    uchar handshake_header[] = {0x02, 0x00, 0x00, 0x00};
    // uint32_t record_header_len, handshake_header_len;
    uchar server_version[] = {0x03, 0x03};
    uchar server_random[32];
    uchar *session_id = malloc(33 * sizeof(uchar));
    uchar cipher_suite[] = {0x13, 0x02};
    uchar compression_method[] = {0x00};
    uchar extensions_length[2];
    uint32_t extension_len;
    uchar supported_versions[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    uchar key_share_header[] = {0x00, 0x33, 0x04, 0x64, 0x63, 0x99, 0x04, 0x60};

    uchar client_hello[USHRT_MAX];
    ssize_t client_hello_len;
    uint32_t server_hello_len, server_hello_response_len;
    uchar *server_hello = malloc(USHRT_MAX * sizeof(uchar));
    uchar *server_share_key = malloc(1120 * sizeof(uchar));
    uchar *server_hello_response = NULL;
    uchar *X25519_client_pk = malloc(32 * sizeof(uchar));
    uchar *X25519_server_pk = malloc(32 * sizeof(uchar));
    uchar *X25519_server_sk = malloc(32 * sizeof(uchar));
    uchar *X25519_ss = malloc(32 * sizeof(uchar));
    uchar *Kyber768_pk = malloc(1184 * sizeof(uchar));
    uchar *kyber_ct = malloc(1088 * sizeof(uchar));
    uchar *kyber_ss = malloc(32 * sizeof(uchar));
    uchar *ss = malloc(64 * sizeof(uchar));
    uchar change_cipher_spec[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

    uchar *hello_msg = NULL;
    uchar *hello_hash = NULL;
    size_t hello_msg_len;
    uchar *handshake_secret = malloc(SHA384_DIGEST_LENGTH * sizeof(uchar));
    uchar *server_handshake_traffic_secret = malloc(SHA384_DIGEST_LENGTH * sizeof(uchar));
    uchar *client_handshake_traffic_secret = malloc(SHA384_DIGEST_LENGTH * sizeof(uchar));
    uchar *server_handshake_key = malloc(AES_KEY_LENGTH_256 * sizeof(uchar));
    uchar *client_handshake_key = malloc(AES_KEY_LENGTH_256 * sizeof(uchar));
    uchar *server_handshake_iv = malloc(GCM_IV_LENGTH * sizeof(uchar));
    uchar *client_handshake_iv = malloc(GCM_IV_LENGTH * sizeof(uchar));

    // init encryption args
    EVP_CIPHER_CTX *ctx;
    // uchar key[EVP_MAX_KEY_LENGTH] = "your-256-bit-key"; // 256 bits key
    uchar *iv = NULL;
    uchar aad[5];
    uint64_t server_hs_seq = 0, client_hs_seq = 0;
    uchar *tag = malloc(TAG_SIZE * sizeof(uchar));
    uchar *pt = NULL;
    uchar *ct = malloc(BUFFER_SIZE * sizeof(uchar));
    int outlen, pt_len, ct_len;

    uchar wrap_record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    uchar handshake_record_type[] = {0x16};
    uint32_t wrap_record_header_len = 5, wrap_len;

    uchar *wrap_server_extentions = NULL;
    uchar server_extension[] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
    uint32_t server_extention_len = 6, wrap_server_extentions_len;

    uchar *wrap_server_crt = NULL;
    uchar *server_crt = NULL;
    uchar crt_handshake_header[] = {0x0b, 0x00, 0x00, 0x00};
    uchar crt_req_ctx[] = {0x00};
    uchar crts_length[] = {0x00, 0x00, 0x00};
    uchar crt_length[] = {0x00, 0x00, 0x00};
    uchar *crt = malloc(CRT_SIZE * sizeof(uchar));
    uint32_t crt_len, server_crt_len, wrap_server_crt_len;
    uchar crt_extensions[] = {0x00, 0x00};

    uchar *wrap_server_crt_verify = NULL;
    uchar *server_crt_verify = NULL;
    uchar crt_verify_handshake_header[] = {0x0f, 0x00, 0x00, 0x00};
    uchar signature_header[] = {0x08, 0x04, 0x00, 0x00}; // RSA-PSS-RSAE-SHA256 (0x08, 0x04), RSA-PSS-RSAE-SHA384 (0x08, 0x05)
    uchar *handshake_msg = NULL;
    uchar *handshake_hash = NULL;
    uchar *to_sign = NULL;
    uchar space_64[64];
    memset(space_64, 0x20, sizeof(space_64));
    uchar sign_fixed_str[] = "TLS 1.3, server CertificateVerify\0";
    uchar *signature = NULL;
    uint32_t handshake_msg_len, to_sign_len, server_crt_verify_len, wrap_server_crt_verify_len;
    size_t sign_len;

    uchar *wrap_handshake_finished = NULL;
    uchar *server_handshake_finished = NULL;
    uchar handshake_finished_header[] = {0x14, 0x00, 0x00, 0x30}; // sha384
    uchar *finish_key = NULL;
    uchar *finish_hash = NULL;
    uchar *verify_data = NULL;
    uint32_t finished_header_len = 4, server_handshake_finished_len, wrap_server_handshake_finished_len;

    uint64_t server_ap_seq = 0, client_ap_seq = 0;
    uchar *all_handshake_hash = malloc(SHA384_DIGEST_LENGTH * sizeof(uchar));
    uchar *server_application_key = malloc(AES_KEY_LENGTH_256 * sizeof(uchar));
    uchar *client_application_key = malloc(AES_KEY_LENGTH_256 * sizeof(uchar));
    uchar *server_application_iv = malloc(GCM_IV_LENGTH * sizeof(uchar));
    uchar *client_application_iv = malloc(GCM_IV_LENGTH * sizeof(uchar));
    uchar application_data_record_type[] = {0x17};

    uchar *enc_application_data = NULL;
    uint32_t enc_application_data_len;

    createProxySocket();
    signal(SIGINT, sigint_handler);
    
    // while(1) {
        client_sock = accept(proxy_sock, (struct sockaddr *)&client_addr, &client_addr_size);
        loadTimeoutSetting(client_sock);
        if(client_sock < 0) error("ERROR on accept.\n");
        else {
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("\n(Connection count:%d)\n==============================\n", ++connectionCount);
            printf("Accept client IP:%s\n", client_ip);
        }
        
        if(!TLS_handshake_state){

            /* read test server hello */
            // read_file(server_hello, &len, "sh_test2.txt", 1);
            // printf("Server hello(%d bytes):\n", len);
            // print_bytes(server_hello, len);

            /* read client hello */
            client_hello_len = 0;
            while((bytes = recv(client_sock, client_hello, USHRT_MAX, 0)) > 0){
                printf("Client hello (length:%zd):\n", bytes);
                print_bytes(client_hello, bytes);
                printf("\n");
                client_hello_len += bytes;
            }
            // printf("client hello bytes: %zd\n", client_hello_len);
            parse_client_hello(client_hello, client_hello_len, session_id, X25519_client_pk, Kyber768_pk);
            // send_response(client_sock, server_hello, len);

            // printf("Session ID:\n");
            // print_bytes(session_id, 33);
            // printf("\n");
            // printf("X25519 client pk:\n");
            // print_bytes(X25519_client_pk, 32);
            // printf("\n");
            // printf("Kyber768 pk:\n");
            // print_bytes(Kyber768_pk, 1184);
            // printf("\n");


            /* generate server x25519 keypair */
            x25519_keygen(X25519_server_sk, X25519_server_pk);
            
            // printf("X25519 server pk:\n");
            // print_bytes(X25519_server_pk, 32);
            // printf("\n");
            // printf("X25519 server sk:\n");
            // print_bytes(X25519_server_sk, 32);
            // printf("\n");


            /* Generate kyber share secret & Ciphertext encapsulation using client's public key */
            crypto_kem_enc(kyber_ct, kyber_ss, Kyber768_pk);
            // printf("Kyber ct:\n");
            // print_bytes(kyber_ct, 1088);
            // printf("\n");
            // printf("Kyber ss:\n");
            // print_bytes(kyber_ss, 32);
            // printf("\n");

            /* concat & send response */
            server_share_key = concat_uc_str(X25519_server_pk, 32, kyber_ct, 1088);
            // server_hello_response = realloc(server_hello_response ,(len + 1120 + 6) * sizeof(uchar));
            // server_hello_response = concat_uc_str(server_hello, len, server_share_key, 1120);
            // server_response_len = len + 1120;
            // server_hello_response = concat_uc_str(server_hello_response, server_response_len, change_cipher_spec, 6);
            // server_response_len += 6;
            
            // printf("Server hello:\n");
            // print_bytes(server_hello_response, server_response_len);
            // printf("\n");

            /* gen server hello */
            server_hello_len = 0;
            extension_len = 0;
            server_hello = concat_uc_str(server_hello, server_hello_len, supported_versions, 6);
            server_hello_len += 6;
            extension_len += 6;
            server_hello = concat_uc_str(server_hello, server_hello_len, key_share_header, 8);
            server_hello_len += 8;
            extension_len += 8;
            server_hello = concat_uc_str(server_hello, server_hello_len, server_share_key, 1120);
            server_hello_len += 1120;
            extension_len += 1120;
            insert_header_len(extensions_length, extension_len, 0, 1);
            server_hello = concat_uc_str(extensions_length, 2, server_hello, server_hello_len);
            server_hello_len += 2;
            server_hello = concat_uc_str(compression_method, 1, server_hello, server_hello_len);
            server_hello_len += 1;
            server_hello = concat_uc_str(cipher_suite, 2, server_hello, server_hello_len);
            server_hello_len += 2;
            server_hello = concat_uc_str(session_id, 33, server_hello, server_hello_len);
            server_hello_len += 33;
            get_random(server_random);
            server_hello = concat_uc_str(server_random, 32, server_hello, server_hello_len);
            server_hello_len += 32;
            server_hello = concat_uc_str(server_version, 2, server_hello, server_hello_len);
            server_hello_len += 2;
            insert_header_len(handshake_header, server_hello_len, 1, 3);
            server_hello = concat_uc_str(handshake_header, 4, server_hello, server_hello_len);
            server_hello_len += 4;
            insert_header_len(record_header, server_hello_len, 3, 4);
            server_hello = concat_uc_str(record_header, 5, server_hello, server_hello_len);
            server_hello_len += 5;

            // Change cipher spec
            // server_hello = concat_uc_str(server_hello, server_hello_len, change_cipher_spec, 6);
            // server_hello_len += 6;

            // printf("Server hello:\n");
            // print_bytes(server_hello, server_hello_len);
            // printf("\n");
            
            // send_response(client_sock, server_hello, server_hello_len);
            // send(client_sock, server_hello_response, server_response_len, 0);

            /* calculate all key */

            /* calculate x25519 share secret (method 1) */
            // EVP_PKEY *sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, X25519_server_sk, 32);
            // EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, X25519_client_pk, 32);
            // EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
            // if (!ctx) {
            //     // handle error
            // }
            // if (EVP_PKEY_derive_init(ctx) <= 0) {
            //     // handle error
            // }
            // if (EVP_PKEY_derive_set_peer(ctx, pk) <= 0) {
            //     // handle error
            // }

            // // derive ss
            // size_t secret_len;
            // EVP_PKEY_derive(ctx, NULL, &secret_len);
            // uchar *secret = malloc(secret_len);
            // if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
            //     // handle error
            // }

            // // print secret
            // printf("X25519 ss:\n");
            // print_bytes(secret, secret_len);
            // printf("\n");

            // // clear
            // EVP_PKEY_CTX_free(ctx);
            // free(secret);
            // EVP_PKEY_free(sk);
            // EVP_PKEY_free(pk);

            /* calculate x25519 share secret (method 2) */
            curve25519_donna(X25519_ss, X25519_server_sk, X25519_client_pk);
            // printf("X25519 ss:\n");
            // print_bytes(X25519_ss, 32);
            // printf("\n");

            /* concat X25519 & Kyber768 ss */
            ss = concat_uc_str(X25519_ss, 32, kyber_ss, 32);
            // printf("Shared secret:\n");
            // print_bytes(ss, SS_LEN);
            // printf("\n");

            /* calculate handshake key */
            hello_msg = concat_uc_str(client_hello + 5, client_hello_len - 5, server_hello + 5, server_hello_len - 5);
            hello_msg_len = client_hello_len - 5 + server_hello_len - 5;
            // printf("Hello msg:\n");
            // print_bytes(hello_msg, hello_msg_len);
            // printf("\n");
            hello_hash = sha384(hello_msg, hello_msg_len);
            // printf("Hello hash:\n");
            // print_bytes(hello_hash, SHA384_DIGEST_LENGTH);
            // printf("\n");

            handshake_key_calc(hello_hash, ss, &handshake_secret, &server_handshake_traffic_secret, &client_handshake_traffic_secret, &server_handshake_key, &client_handshake_key, &server_handshake_iv, &client_handshake_iv);
            // printf("hs: ");
            // print_bytes(handshake_secret, 48);
            // printf("ssec: ");
            // print_bytes(server_handshake_traffic_secret, 48);
            // printf("csec: ");
            // print_bytes(client_handshake_traffic_secret, 48);
            // printf("skey: ");
            // print_bytes(server_handshake_key, 32);
            // printf("ckey: ");
            // print_bytes(client_handshake_key, 32);
            // printf("siv: ");
            // print_bytes(server_handshake_iv, 12);
            // printf("civ: ");
            // print_bytes(client_handshake_iv, 12);
            // printf("\n");


            /* calc server extenstions (record 1)*/
            wrap_len = 6 + 1 + TAG_SIZE;
            insert_header_len(wrap_record_header, wrap_len, 3, 4);

            // printf("Wrap record header (server extension):\n");
            // print_bytes(wrap_record_header, wrap_record_header_len);

            pt = concat_uc_str(server_extension, server_extention_len, handshake_record_type, 1);
            pt_len = server_extention_len + 1;
            // printf("pt:\n");
            // print_bytes(pt, pt_len);

            ct_len = 0, outlen = 0;
            iv = build_iv(server_handshake_iv, &server_hs_seq);
            // printf("server_hs_seq: %llu\n", server_hs_seq);
            // printf("iv:\n");
            // print_bytes(iv, GCM_IV_LENGTH);
            evp_enc_init(&ctx, server_handshake_key, iv);
            enc_update(ctx, wrap_record_header, wrap_record_header_len, NULL, &ct_len, &outlen);
            enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
            complete_enc(&ctx, ct, &ct_len, &outlen, tag);
            // printf("ct:\n");
            // print_bytes(ct, ct_len);

            // printf("tag:\n");
            // print_bytes(tag, TAG_SIZE);
            // printf("\n");

            if(ct_len + TAG_SIZE != wrap_len)
                printf("Wrap record encryption error.\n");
            else{
                wrap_server_extentions = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
                wrap_server_extentions = concat_uc_str(wrap_record_header, wrap_record_header_len, wrap_server_extentions, wrap_len);
            }

            wrap_server_extentions_len = wrap_record_header_len + wrap_len;
            // printf("Wrap record 1 (len: %d):\n", wrap_len);
            // print_bytes(wrap_server_extentions, wrap_server_extentions_len);
            // printf("\n");
            
            

            /* calc server crt (record 2) */
            // clear enc args
            iv = NULL;
            pt = NULL;
            memset(ct, 0, BUFFER_SIZE * sizeof(uchar));
            memset(tag, 0, TAG_SIZE * sizeof(uchar));
            pt_len = 0, ct_len = 0, outlen = 0;

            // load_certificates("cert/rootCA.der", &crt, &crt_len);
            // printf("Loaded root CA certificate (len: %d):\n", crt_len);
            // print_bytes(crt, crt_len);
            // printf("\n");
            
            // server_crt = concat_uc_str(crt, crt_len, crt_extensions, 2);
            // server_crt_len = crt_len + 2;
            // insert_header_len(crt_length, crt_len, 0, 2); // only crt length
            // server_crt = concat_uc_str(crt_length, 3, server_crt, server_crt_len);
            // server_crt_len += 3;
            
            // printf("Server crt_0:\n");
            // print_bytes(server_crt, server_crt_len);
            // printf("\n\n");

            /* intermediateCA */
            /*
            // memset(crt, 0, crt_len);
            load_certificates("cert/intermediateCA.der", &crt, &crt_len);
            // printf("Loaded intermediate CA certificate (len: %d):\n", crt_len);
            // print_bytes(crt, crt_len);
            // printf("\n");

            server_crt = concat_uc_str(crt, crt_len, crt_extensions, 2);
            server_crt_len = crt_len + 2;
            // server_crt = concat_uc_str(crt_extensions, 2, server_crt, server_crt_len);
            // server_crt_len += 2;
            // server_crt = concat_uc_str(crt, crt_len, server_crt, server_crt_len);
            // server_crt_len += crt_len;
            insert_header_len(crt_length, crt_len, 0, 2); // only crt length
            server_crt = concat_uc_str(crt_length, 3, server_crt, server_crt_len);
            server_crt_len += 3;
            
            // printf("Server crt_1:\n");
            // print_bytes(server_crt, server_crt_len);
            // printf("\n\n");
            */
            /* intermediateCA */

            memset(crt, 0, crt_len);
            // load_certificates("cert/server.der", &crt, &crt_len);
            load_certificates("cert/www.pqc-demo.xyz.der", &crt, &crt_len);
            // printf("Loaded server certificate (len: %d):\n", crt_len);
            // print_bytes(crt, crt_len);
            // printf("\n");


            server_crt = concat_uc_str(crt, crt_len, crt_extensions, 2);
            server_crt_len = crt_len + 2;
            // server_crt = concat_uc_str(crt_extensions, 2, server_crt, server_crt_len);
            // server_crt_len += 2;
            // server_crt = concat_uc_str(crt, crt_len, server_crt, server_crt_len);
            // server_crt_len += crt_len;
            insert_header_len(crt_length, crt_len, 0, 2); // only crt length
            server_crt = concat_uc_str(crt_length, 3, server_crt, server_crt_len);
            server_crt_len += 3;

            // printf("Server crt_2:\n");
            // print_bytes(server_crt, server_crt_len);
            // printf("\n\n");

            insert_header_len(crts_length, server_crt_len, 0, 2); // crts length
            server_crt = concat_uc_str(crts_length, 3, server_crt, server_crt_len);
            server_crt_len += 3;
            server_crt = concat_uc_str(crt_req_ctx, 1, server_crt, server_crt_len);
            server_crt_len += 1;
            insert_header_len(crt_handshake_header, server_crt_len, 1, 3);
            server_crt = concat_uc_str(crt_handshake_header, 4, server_crt, server_crt_len);
            server_crt_len += 4;

            // printf("Server crt:\n");
            // print_bytes(server_crt, server_crt_len);
            // printf("\n\n");
            
            wrap_len =  server_crt_len + 1 + TAG_SIZE;
            insert_header_len(wrap_record_header, wrap_len, 3, 4);
            // printf("Wrap record header (server extension):\n");
            // print_bytes(wrap_record_header, wrap_record_header_len);

            pt = concat_uc_str(server_crt, server_crt_len, handshake_record_type, 1);
            pt_len = server_crt_len + 1;
            // printf("pt:\n");
            // print_bytes(pt, pt_len);

            iv = build_iv(server_handshake_iv, &server_hs_seq);
            // printf("server_hs_seq: %llu\n", server_hs_seq);
            // printf("iv:\n");
            // print_bytes(iv, GCM_IV_LENGTH);
            evp_enc_init(&ctx, server_handshake_key, iv);
            enc_update(ctx, wrap_record_header, wrap_record_header_len, NULL, &ct_len, &outlen);
            enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
            complete_enc(&ctx, ct, &ct_len, &outlen, tag);
            // printf("ct:\n");
            // print_bytes(ct, ct_len);

            // printf("tag:\n");
            // print_bytes(tag, TAG_SIZE);
            // printf("\n");

            if(ct_len + TAG_SIZE != wrap_len)
                printf("Wrap record encryption error.\n");
            else{
                wrap_server_crt = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
                wrap_server_crt = concat_uc_str(wrap_record_header, wrap_record_header_len, wrap_server_crt, wrap_len);
            }

            wrap_server_crt_len = wrap_record_header_len + wrap_len;
            // printf("Wrap record 2 (len: %d):\n", wrap_len);
            // print_bytes(wrap_server_crt, wrap_server_crt_len);
            // printf("\n");


            /* calc crt verify (record 3) */

            // clear enc args
            iv = NULL;
            pt = NULL;
            memset(ct, 0, BUFFER_SIZE * sizeof(uchar));
            memset(tag, 0, TAG_SIZE * sizeof(uchar));
            pt_len = 0, ct_len = 0, outlen = 0;

            // printf("Hello msg(len: %zu):\n", hello_msg_len);
            // print_bytes(hello_msg, hello_msg_len);
            // printf("\n");

            to_sign = concat_uc_str(space_64, 64, sign_fixed_str, strlen((char *)sign_fixed_str) + 1);
            to_sign_len = 64 + strlen((char *)sign_fixed_str) + 1;
            
            // printf("len:%lu\n", strlen((char *)sign_fixed_str));
            // printf("handshake msg_00 (len: %d):\n", handshake_msg_len);
            // print_bytes(handshake_msg, handshake_msg_len);
            // printf("\n");

            handshake_msg = concat_uc_str(hello_msg, hello_msg_len, server_extension, 6);
            handshake_msg_len += hello_msg_len + 6;
            handshake_msg = concat_uc_str(handshake_msg, handshake_msg_len, server_crt, server_crt_len);
            handshake_msg_len += server_crt_len;

            // printf("handshake msg:\n");
            // print_bytes(handshake_msg, handshake_msg_len);
            // printf("\n");

            // handshake_hash = sha256(handshake_msg, handshake_msg_len);
            handshake_hash = sha384(handshake_msg, handshake_msg_len);

            to_sign = concat_uc_str(to_sign, to_sign_len, handshake_hash, SHA384_DIGEST_LENGTH);
            to_sign_len += SHA384_DIGEST_LENGTH;

            // printf("handshake msg hash:\n");
            // print_bytes(handshake_hash, SHA384_DIGEST_LENGTH);
            // printf("\n");

            // signature = sign_msg(handshake_hash, SHA256_DIGEST_LENGTH, SIGN_ALG, &sign_len);
            signature = sign_msg(to_sign, to_sign_len, SIGN_ALG, &sign_len);

            // printf("signature:\n");
            // print_bytes(signature, sign_len);
            // printf("\n");

            // if(verify_msg(handshake_hash, SHA256_DIGEST_LENGTH, SIGN_ALG, signature, sign_len))
            //     printf("Verification successful.\n\n");
            // else
            //     printf("Verification failed.\n\n");

            // if(verify_msg(handshake_hash, SHA384_DIGEST_LENGTH, SIGN_ALG, signature, sign_len))
            //     printf("Verification successful.\n\n");
            // else
            //     printf("Verification failed.\n\n");

            insert_header_len(signature_header, sign_len, 2, 3);
            signature = concat_uc_str(signature_header, 4, signature, sign_len);
            sign_len += 4;

            insert_header_len(crt_verify_handshake_header, sign_len, 1, 3);
            server_crt_verify = concat_uc_str(crt_verify_handshake_header, 4, signature, sign_len);
            server_crt_verify_len = 4 + sign_len;

            // printf("server crt verify:\n");
            // print_bytes(server_crt_verify, server_crt_verify_len);
            // printf("\n");

            wrap_len =  server_crt_verify_len + 1 + TAG_SIZE;
            insert_header_len(wrap_record_header, wrap_len, 3, 4);
            // printf("Wrap record header (server extension):\n");
            // print_bytes(wrap_record_header, wrap_record_header_len);

            pt = concat_uc_str(server_crt_verify, server_crt_verify_len, handshake_record_type, 1);
            pt_len = server_crt_verify_len + 1;
            // printf("pt:\n");
            // print_bytes(pt, pt_len);

            iv = build_iv(server_handshake_iv, &server_hs_seq);
            // printf("server_hs_seq: %llu\n", server_hs_seq);
            // printf("iv:\n");
            // print_bytes(iv, GCM_IV_LENGTH);
            evp_enc_init(&ctx, server_handshake_key, iv);
            enc_update(ctx, wrap_record_header, wrap_record_header_len, NULL, &ct_len, &outlen);
            enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
            complete_enc(&ctx, ct, &ct_len, &outlen, tag);
            // printf("ct:\n");
            // print_bytes(ct, ct_len);

            // printf("tag:\n");
            // print_bytes(tag, TAG_SIZE);
            // printf("\n");

            if(ct_len + TAG_SIZE != wrap_len)
                printf("Wrap record encryption error.\n");
            else{
                wrap_server_crt_verify = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
                wrap_server_crt_verify = concat_uc_str(wrap_record_header, wrap_record_header_len, wrap_server_crt_verify, wrap_len);
            }
            
            wrap_server_crt_verify_len = wrap_record_header_len + wrap_len;
            // printf("wrap record 3 (len: %d):\n", wrap_len);
            // print_bytes(wrap_server_crt_verify, wrap_server_crt_verify_len);
            // printf("\n");


            /* calc verify data (record 4) */

            // clear enc args
            iv = NULL;
            pt = NULL;
            memset(ct, 0, BUFFER_SIZE * sizeof(uchar));
            memset(tag, 0, TAG_SIZE * sizeof(uchar));
            pt_len = 0, ct_len = 0, outlen = 0;

            finish_key = derive_secret(server_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "finished", (uchar *)"", 0, SHA384_DIGEST_LENGTH);
            handshake_msg = concat_uc_str(handshake_msg, handshake_msg_len, server_crt_verify, server_crt_verify_len);
            handshake_msg_len += server_crt_verify_len;
            finish_hash = sha384(handshake_msg, handshake_msg_len);
            verify_data = hmac_sha384(finish_key, SHA384_DIGEST_LENGTH, finish_hash, SHA384_DIGEST_LENGTH);

            // printf("verify data:\n");
            // print_bytes(verify_data, SHA384_DIGEST_LENGTH);
            // printf("\n");

            server_handshake_finished = concat_uc_str(handshake_finished_header, 4, verify_data, SHA384_DIGEST_LENGTH);
            server_handshake_finished_len = 4 + SHA384_DIGEST_LENGTH;

            wrap_len =  server_handshake_finished_len + 1 + TAG_SIZE;
            insert_header_len(wrap_record_header, wrap_len, 3, 4);
            // printf("Wrap record header (server extension):\n");
            // print_bytes(wrap_record_header, wrap_record_header_len);

            pt = concat_uc_str(server_handshake_finished, server_handshake_finished_len, handshake_record_type, 1);
            pt_len = server_handshake_finished_len + 1;
            // printf("pt:\n");
            // print_bytes(pt, pt_len);

            iv = build_iv(server_handshake_iv, &server_hs_seq);
            // printf("server_hs_seq: %llu\n", server_hs_seq);
            // printf("iv:\n");
            // print_bytes(iv, GCM_IV_LENGTH);
            evp_enc_init(&ctx, server_handshake_key, iv);
            enc_update(ctx, wrap_record_header, wrap_record_header_len, NULL, &ct_len, &outlen);
            enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
            complete_enc(&ctx, ct, &ct_len, &outlen, tag);
            // printf("ct:\n");
            // print_bytes(ct, ct_len);

            // printf("tag:\n");
            // print_bytes(tag, TAG_SIZE);
            // printf("\n");

            if(ct_len + TAG_SIZE != wrap_len)
                printf("Wrap record encryption error.\n");
            else{
                wrap_handshake_finished = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
                wrap_handshake_finished = concat_uc_str(wrap_record_header, wrap_record_header_len, wrap_handshake_finished, wrap_len);
            }

            wrap_server_handshake_finished_len = wrap_record_header_len + wrap_len;
            // printf("wrap record 4 (len: %d):\n", wrap_len);
            // print_bytes(wrap_handshake_finished, wrap_server_handshake_finished_len);
            // printf("\n");


            /* build response */
            server_hello_response = concat_uc_str(server_hello, server_hello_len, change_cipher_spec, 6);
            server_hello_response_len = server_hello_len + 6;
            server_hello_response = concat_uc_str(server_hello_response, server_hello_response_len, wrap_server_extentions, wrap_server_extentions_len);
            server_hello_response_len += wrap_server_extentions_len;
            server_hello_response = concat_uc_str(server_hello_response, server_hello_response_len, wrap_server_crt, wrap_server_crt_len);
            server_hello_response_len += wrap_server_crt_len;
            server_hello_response = concat_uc_str(server_hello_response, server_hello_response_len, wrap_server_crt_verify, wrap_server_crt_verify_len);
            server_hello_response_len += wrap_server_crt_verify_len;
            server_hello_response = concat_uc_str(server_hello_response, server_hello_response_len, wrap_handshake_finished, wrap_server_handshake_finished_len);
            server_hello_response_len += wrap_server_handshake_finished_len;

            printf("Server response (len: %d):\n", server_hello_response_len);
            print_bytes(server_hello_response, server_hello_response_len);
            printf("\n");

            if(send_response(client_sock, server_hello_response, server_hello_response_len) != server_hello_response_len)
                printf("send error.\n");


            if((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
                printf("Client response (len: %zd):\n", bytes);
                print_bytes(buffer, bytes);
                printf("\n");
            }

            /* phare client finished */
            if(cmp_uc_str(change_cipher_spec, buffer, 6))
                printf("Recieved change cipher spec.\n\n");
            
            // ignore change cipher spec
            // printf("%zd\n", bytes);
            // printf("Recieved data:\n");
            // print_bytes(buffer + 6, bytes - 6);

            // clear dec args
            iv = NULL;
            memset(aad, 0, 5);
            pt = malloc(BUFFER_SIZE * sizeof(uchar));
            memset(ct, 0, BUFFER_SIZE * sizeof(uchar));
            memset(tag, 0, TAG_SIZE * sizeof(uchar));
            pt_len = 0, ct_len = 0, outlen = 0;

            // get enc data
            if(cmp_uc_str(wrap_record_header, buffer + 6, 3)){
                // printf("data (len: %d):\n", (buffer[9] << 8) + buffer[10]);
                // print_bytes(buffer + 6, bytes - 6);
                memcpy(aad, buffer + 6, 5);
                // printf("aad:\n");
                // print_bytes(aad, 5);
                ct_len = (buffer[9] << 8) + buffer[10] - TAG_SIZE;
                memcpy(ct, buffer + 6 + wrap_record_header_len, ct_len);
                // printf("ct (len: %d):\n", ct_len);
                // print_bytes(ct, ct_len);
                memcpy(tag, buffer + bytes - TAG_SIZE, TAG_SIZE);
                // printf("tag (len: %d)\n", TAG_SIZE);
                // print_bytes(tag, TAG_SIZE);
            }

            // dec
            iv = build_iv(client_handshake_iv, &client_hs_seq);
            evp_dec_init(&ctx, client_handshake_key, iv);
            dec_update(ctx, aad, 5, NULL, &pt_len, &outlen);
            dec_update(ctx, ct, ct_len, pt, &pt_len, &outlen);
            complete_dec(&ctx, pt, &pt_len, &outlen, tag);

            printf("Decrypted verify data:(len: %d):\n", pt_len);
            print_bytes(pt, pt_len);
            printf("\n");
            
            // if((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
            //     printf("Client response (length:%zd):\n", bytes);
            //     print_bytes(buffer, bytes);
            //     printf("\n");
            // }

            /* calc application key*/
            handshake_msg = concat_uc_str(handshake_msg, handshake_msg_len, server_handshake_finished, server_handshake_finished_len);
            handshake_msg_len += server_handshake_finished_len;
            all_handshake_hash = sha384(handshake_msg, handshake_msg_len);
            master_key_calc(all_handshake_hash, handshake_secret, &server_application_key, &server_application_iv, &client_application_key, &client_application_iv);

            TLS_handshake_state = 1;

        }

        memset(buffer, 0, BUFFER_SIZE);

        while((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
            if(bytes == 0) continue;
            printf("(Client) Encrypted application data (bytes: %zd):\n", bytes);
            print_bytes(buffer, bytes);
            printf("\n");
            memset(buffer, 0, BUFFER_SIZE);
        }

        // clear dec args
        // server_ap_seq = 0, client_ap_seq = 0;
        iv = NULL;
        pt = NULL;
        // pt = malloc(BUFFER_SIZE * sizeof(uchar));
        // memset(pt, 0, BUFFER_SIZE * sizeof(uchar));
        memset(ct, 0, BUFFER_SIZE * sizeof(uchar));
        memset(tag, 0, TAG_SIZE * sizeof(uchar));
        pt_len = 0, ct_len = 0, outlen = 0;

        wrap_len =  strlen(testHttpResponse) + 1 + TAG_SIZE;
        insert_header_len(wrap_record_header, wrap_len, 3, 4);

        pt = concat_uc_str((uchar *)testHttpResponse, strlen(testHttpResponse), application_data_record_type, 1);
        pt_len = strlen(testHttpResponse) + 1;

        // print_bytes(pt, pt_len);
        printf("Server plaintext data (len: %d):\n", pt_len);
        for(int i = 0; i < pt_len; i++)
            printf("%c", pt[i]);
        printf("\n");

        iv = build_iv(server_application_iv, &server_ap_seq);

        evp_enc_init(&ctx, server_application_key, iv);
        enc_update(ctx, wrap_record_header, wrap_record_header_len, NULL, &ct_len, &outlen);
        enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
        complete_enc(&ctx, ct, &ct_len, &outlen, tag);

        if(ct_len + TAG_SIZE != wrap_len)
            printf("Application data encryption error.\n");
        else{
            enc_application_data = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
            enc_application_data = concat_uc_str(wrap_record_header, wrap_record_header_len, enc_application_data, wrap_len);
        }
        enc_application_data_len = wrap_record_header_len + wrap_len;
        
        printf("(Server) Encrypted application data (len: %d):\n", enc_application_data_len);
        print_bytes(enc_application_data, enc_application_data_len);
        printf("\n");
        // send(client_sock, testHttpResponse, strlen(testHttpResponse), 0);

        send_response(client_sock, enc_application_data, enc_application_data_len);

        free(enc_application_data);
        enc_application_data = NULL;

        printf("Closing client(IP:%s) socket...", client_ip);
        close(client_sock);
        printf("Done.\nClosing server socket...");
        close(server_sock);
        printf("Done.\n==============================\n");
    // }

    close(proxy_sock);
    

    free(buffer);
    free(session_id);

    free(server_hello);
    free(server_share_key);
    free(server_hello_response);

    free(X25519_client_pk);
    free(X25519_server_pk);
    free(X25519_server_sk);
    free(X25519_ss);
    free(Kyber768_pk);
    free(kyber_ct);
    free(kyber_ss);
    free(ss);

    free(hello_msg);
    free(hello_hash);
    free(handshake_secret);
    free(server_handshake_traffic_secret);
    free(client_handshake_traffic_secret);
    free(server_handshake_key);
    free(client_handshake_key);
    free(server_handshake_iv);
    free(client_handshake_iv);

    free(iv);
    free(tag);
    free(pt);
    free(ct);

    free(wrap_server_extentions);

    free(wrap_server_crt);
    free(server_crt);
    free(crt);

    free(wrap_server_crt_verify);
    free(server_crt_verify);
    free(handshake_msg);
    free(handshake_hash);
    free(to_sign);
    free(signature);

    free(wrap_handshake_finished);
    free(server_handshake_finished);
    free(finish_key);
    free(finish_hash);
    free(verify_data);

    free(all_handshake_hash);
    free(server_application_key);
    free(client_application_key);
    free(server_application_iv);
    free(client_application_iv);
    // free(enc_application_data);
    return 0;
}
