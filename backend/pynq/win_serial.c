#include <pynq/uart.h>
#include <base/base.h>
#include <base/serving.h>
#include <pthread.h>

static void *connect_to_pynq(void *arg){
    pynq_args *args = (pynq_args *)arg;
    int pynq_sock = 0;
    struct sockaddr_in pynq_serv_addr;
    if ((pynq_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n(pynq): Socket creation error \n");
        return NULL;
    }

    pynq_serv_addr.sin_family = AF_INET;
    pynq_serv_addr.sin_port = htons(args->port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "192.168.2.99", &pynq_serv_addr.sin_addr) <= 0) {
        printf("\n(pynq): Invalid address/ Address not supported \n");
        close(pynq_sock);
        return NULL;
    }

    // Connect to the server
    if (connect(pynq_sock, (struct sockaddr *)&pynq_serv_addr, sizeof(pynq_serv_addr)) < 0) {
        printf("\n(pynq): Connection Failed \n");
        close(pynq_sock);
        return NULL;
    }
    
    send(pynq_sock, args->pk, KYBER_PUBLICKEYBYTES, 0);
    read(pynq_sock, args->ct, KYBER_CIPHERTEXTBYTES);
    read(pynq_sock, args->ss, KYBER_SECRETKEYBYTES);

    printf("(pynq): CT in thread:\n");
    print_bytes(args->ct, KYBER_CIPHERTEXTBYTES);
    printf("(pynq): SS in thread:\n");
    print_bytes(args->ss, KYBER_SSBYTES);
    close(pynq_sock);
    return NULL;
}

size_t fpga_kyber768(u8 *ct, u8 *ss, const u8 *pk){
    pthread_t thread1;
    pynq_args *args = malloc(sizeof(pynq_args));
    if (args == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }
    args->port = 9999;
    args->pk = (u8 *)pk;
    print_bytes(args->pk, KYBER_PUBLICKEYBYTES);
    args->ct = ct;
    args->ss = ss;

    pthread_create(&thread1, NULL, connect_to_pynq, (void *)args);
    pthread_join(thread1, NULL);

    printf("(pynq): CT:\n");
    print_bytes(args->ct, KYBER_CIPHERTEXTBYTES);
    printf("(pynq): SS:\n");
    print_bytes(args->ss, KYBER_SSBYTES);

    return 1;
}

// int main(){
//     call_fpga_uart();
//     return 0;
// }