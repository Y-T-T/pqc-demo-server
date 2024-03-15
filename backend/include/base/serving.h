#ifndef SERVING_H
#define SERVING_H

#include <base/types.h>

size_t send_msg(int sockfd, BUFFER_POOL *pool, const size_t pool_idx);
ssize_t send_response(int sockfd, const u8* data, size_t data_len);
size_t recv_msg(int sockfd, BUFFER_POOL *pool, size_t *pool_idx);
char * getHeaderExtension(const char *client_ip);
char * insertXFor(char *buffer, const char *client_ip);
size_t update_forwarded_header(BUFFER_POOL *pool, const size_t pool_idx, const char *ip);
void send_backend_response(int sockfd, const char *filename, const char *filetype);
void read_file(u8 **data, uint64_t *len, const char *filename, int type);
char * getFileType(char *filename);
void parseRequest(int sockfd, char *buffer);

#endif