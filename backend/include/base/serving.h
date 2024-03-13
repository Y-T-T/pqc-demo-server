#ifndef SERVING_H
#define SERVING_H

#include <base/base.h>

ssize_t send_response(int sockfd, const u8* data, size_t data_len);
void send_backend_response(int sockfd, const char *filename, const char *filetype);
void read_file(u8 **data, uint64_t *len, const char *filename, int type);
char * getFileType(char *filename);
void parseRequest(int sockfd, char *buffer);

#endif