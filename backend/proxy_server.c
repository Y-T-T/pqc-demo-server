#include <base/base.h>
#include <base/types.h>
#include <base/serving.h>
#include <crypto/x25519kyber768draft00.h>
#include <tls/handshake.h>
#include <tls/tls13_enc_dec.h>
#include <tls/tls13_hkdf_expand.h>

int proxy_sock, client_sock, server_sock;
struct sockaddr_in proxy_addr, client_addr, server_addr;

void sigint_handler(int sig){
    printf("\nClosing proxy socket...");
    close(proxy_sock);
    printf("Done.\nExit.\n");
    exit(0);
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
    proxy_addr.sin_port = htons(PROXY_PORT);

    if (bind(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) error("ERROR on binding.\n");
    else printf("Proxy socket bind on port %d.\n", PROXY_PORT);

    if (listen(proxy_sock, 10) < 0) error("Listen failed");
    else printf("Listening on port %d...\n", PROXY_PORT);
}

void connectToGunicornServer(){
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    loadTimeoutSetting(server_sock);
    if (server_sock < 0) error("ERROR creating socket to server.\n");
    else printf("The socket to server created.\n");

    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    server_addr.sin_port = htons(SERVER_PORT);

    if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) error("ERROR connecting to server.\n");
    else printf("Connected to server.\n");
}

int main() {
    socklen_t client_addr_size = sizeof(client_addr);
    u8 buffer[BUFFER_SIZE];
    BUFFER_POOL buffer_pool[MAX_POOL_SIZE];
    size_t buffer_pool_idx;
    char client_ip[INET_ADDRSTRLEN];
    ssize_t bytes, buffer_len;
    // uint32_t req_len;
    int connectionCount = 0;
    char *testHttpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World!";

    TRANSCRIPT_HASH_MSG transcript_hash_msg = {NULL, 0, NULL, 0};
    HANDSHAKE_HELLO_MSG_CTX client_hello, server_hello;

    SERVER_HELLO_MSG server_hello_response;
    u8 client_hello_msg[BUFFER_SIZE];
    ssize_t client_hello_msg_len;

    TLS13_KEY_EXCHANGE_CTX key_ctx;
    SESSION_POOL session_pool[MAX_POOL_SIZE];
    u8 *session_ticket_msg = NULL;
    size_t session_pool_len = 0, session_ticket_msg_len;

    createProxySocket();
    signal(SIGINT, sigint_handler);
    
    while(1) {
        client_sock = accept(proxy_sock, (struct sockaddr *)&client_addr, &client_addr_size);
        loadTimeoutSetting(client_sock);
        if(client_sock < 0) error("ERROR on accept.\n");
        else {
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("\n(Connection count:%d)\n==============================\n", ++connectionCount);
            printf("Accept client IP:%s\n", client_ip);
        }
        
        /* read client hello */
        client_hello_msg_len = 0;
        memset(buffer, 0, BUFFER_SIZE);
        memset(client_hello_msg, 0, BUFFER_SIZE);
        while((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
            printf("Client hello (length:%zd):\n", bytes);
            print_bytes(buffer, bytes);
            printf("\n");
            memcpy(client_hello_msg + client_hello_msg_len, buffer, bytes);
            client_hello_msg_len += bytes;
        }
        parse_client_hello(client_hello_msg, client_hello_msg_len, &client_hello);

        /* to-do: check session ticket */
        // pool_idx = check_session_ticket(&client_hello, session_pool, session_pool_len);
        client_hello.extensions.session_ticket.valid = 0;
        
        if(!client_hello.extensions.session_ticket.valid){
            update_transcript_hash_msg(&transcript_hash_msg, client_hello_msg + 5, client_hello_msg_len - 5);
            
            /* Generate:
             * 1. Server x25519 keypair
             * 2. Kyber share secret
             * 3. Ciphertext encapsulation using client's public key
             */

            X25519_KYBER768_KEYGEN(client_hello, &server_hello);

            /* Build:
             * server hello
             */

            build_server_hello(&server_hello_response, client_hello, &server_hello);
            update_transcript_hash_msg(&transcript_hash_msg, server_hello_response.hello_msg + 5, server_hello_response.hello_msg_len - 5);

            /* Add:
             * change cipher spec
             */

            add_change_cipher_spec(&server_hello_response);

            /* calculate all key 
             * 1. calc share secret
             * 2. transcript hash of hello msg
             * 3. handshake key derived
             */

            TLS13_KEY_EXCHANGE_CTX_INIT(&key_ctx);
            key_ctx.shared_secret = calc_ss(client_hello, server_hello);

            handshake_key_calc(transcript_hash_msg.hash, &key_ctx);

            /* encrypted wrap record
             * 1. server extenstions
             * 2. server certificate
             * 3. server certificate verify
             * 4. server handshake finished
             */

            enc_server_ext(&server_hello_response, &key_ctx, &transcript_hash_msg);
            enc_server_cert(&server_hello_response, &key_ctx, &transcript_hash_msg);
            enc_server_cert_verify(&server_hello_response, &key_ctx, &transcript_hash_msg);
            enc_server_handshake_finished(&server_hello_response, &key_ctx, &transcript_hash_msg);

            /* calc master key*/
            master_key_calc(&key_ctx, transcript_hash_msg);

            /* Send response */
            if(send_response(client_sock, server_hello_response.all_msg, server_hello_response.all_msg_len) != server_hello_response.all_msg_len)
                printf("send error.\n");
            
            printf("Server send:\n");
            print_bytes(server_hello_response.all_msg, server_hello_response.all_msg_len);
            printf("\n");

            /* recieve client finished */
            buffer_len = 0;
            if((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
                printf("Client response (len: %zd):\n", bytes);
                print_bytes(buffer, bytes);
                printf("\n");
                buffer_len += bytes;
            }

            /* verify client finished */
            if(verify_client_finished(buffer, buffer_len, &key_ctx, transcript_hash_msg))
                printf("Error: Client finished data verified failed.\n");
            else printf("Client finished data verified success.\n");
            
            /* Send 2 session ticket */
            session_ticket_msg = generate_session_ticket(&key_ctx, session_pool, &session_pool_len, &session_ticket_msg_len);
            printf("Session ticket 1:\n");
            print_bytes(session_ticket_msg, session_ticket_msg_len);
            if(send_response(client_sock, session_ticket_msg, session_ticket_msg_len) != session_ticket_msg_len)
                printf("send error.\n");
            
            memset(session_ticket_msg, 0, session_ticket_msg_len);
            session_ticket_msg = generate_session_ticket(&key_ctx, session_pool, &session_pool_len, &session_ticket_msg_len);
            printf("Session ticket 2:\n");
            print_bytes(session_ticket_msg, session_ticket_msg_len);
            if(send_response(client_sock, session_ticket_msg, session_ticket_msg_len) != session_ticket_msg_len)
                printf("send error.\n");
        }
        else {
            /* to-do:
             * Since the ticket is valid, server must response server hello with specific extension
             * ...
             */
            // update_transcript_hash_msg(&transcript_hash_msg, client_hello_msg + 5, client_hello_msg_len - 5);

            // TLS13_KEY_EXCHANGE_CTX_INIT(&key_ctx);
            // key_ctx = *session_pool->key_ctx;
            
        }

        TRANSCRIPT_HASH_MSG_FREE(&transcript_hash_msg);
        SERVER_HELLO_MSG_FREE(&server_hello_response);
        HANDSHAKE_HELLO_MSG_CTX_FREE(&client_hello);
        HANDSHAKE_HELLO_MSG_CTX_FREE(&server_hello);

        printf("\nTLS handshake ends.\n");
        printf("==============================\n");
        printf("Start data exchange.\n");
        printf("==============================\n");
        printf("\n");

        connectToGunicornServer();

        /* recieve applicaion data */

        recv_msg(client_sock, buffer_pool, &buffer_pool_idx);
        // for(int i = 0; i < buffer_pool_idx; i++){
        //     printf("Pool[%d]: Recieved:(len: %zd):\n", i, buffer_pool[i].length);
        //     print_bytes(buffer_pool[i].buffer, buffer_pool[i].length);
        // }

        client_msg_dec(buffer_pool, buffer_pool_idx, &key_ctx);
        // for(int i = 0; i < buffer_pool_idx; i++)
        //     printf("Pool[%d]: Decryped:(len: %zd):\n%s\n", i, buffer_pool[i].length, buffer_pool[i].buffer);
        
        update_forwarded_header(buffer_pool, buffer_pool_idx, client_ip);
        // for(int i = 0; i < buffer_pool_idx; i++)
        //     printf("Pool[%d]: Add X-Forwarded:(len: %zd):\n%s\n", i, buffer_pool[i].length, buffer_pool[i].buffer);

        send_msg(server_sock, buffer_pool, buffer_pool_idx);

        recv_msg(server_sock, buffer_pool, &buffer_pool_idx);
        if(server_msg_enc(buffer_pool, buffer_pool_idx, &key_ctx))
            send_msg(client_sock, buffer_pool, buffer_pool_idx);

        // printf("Server response(length:%lu):\n", strlen(testHttpResponse));
        // printf("%s\n", testHttpResponse);
        // enc_data_len = server_msg_enc((u8 *)testHttpResponse, strlen(testHttpResponse), &key_ctx, enc_data);
        // printf("Server encrypted response(len: %zu):\n", enc_data_len);
        // print_bytes(enc_data, enc_data_len);
        // printf("\n");
       
        // send(client_sock, testHttpResponse, strlen(testHttpResponse), 0);

        printf("Closing client(IP:%s) socket...", client_ip);
        close(client_sock);
        printf("Done.\nClosing server socket...");
        close(server_sock);
        printf("Done.\n==============================\n");
    }

    close(proxy_sock);
    
    TLS13_KEY_EXCHANGE_CTX_FREE(&key_ctx);
    SESSION_POOL_FREE(session_pool, session_pool_len);
    free(session_ticket_msg);

    return 0;
}
