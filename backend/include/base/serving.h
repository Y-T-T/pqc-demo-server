#ifndef SERVING_H
#define SERVING_H

#include <base/types.h>
#include <signal.h>

int proxy_sock, client_sock, server_sock;
struct sockaddr_in proxy_addr, client_addr, server_addr;
volatile sig_atomic_t timeout;

void sigint_handler(int sig);
void handle_alarm(int sig);
void loadProxySetting();
void loadTimeoutSetting(int sockfd);
void createProxySocket();
void connectToGunicornServer();
size_t send_msg(int sockfd, BUFFER_POOL *pool, const size_t pool_idx);
ssize_t send_response(int sockfd, const u8* data, size_t data_len);
size_t recv_msg(int sockfd, BUFFER_POOL *pool, size_t *pool_idx);
size_t update_forwarded_header(BUFFER_POOL *pool, const size_t pool_idx, const char *ip);
size_t conn_is_keep_alive(const BUFFER_POOL *, const size_t);
size_t update_keep_alive_header(BUFFER_POOL *pool, const size_t pool_idx);
void send_backend_response(int sockfd, const char *filename, const char *filetype);
void read_file(u8 **data, uint64_t *len, const char *filename, int type);
char * getFileType(char *filename);
void parseRequest(int sockfd, char *buffer);

#endif