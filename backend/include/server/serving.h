#ifndef SERVING_H
#define SERVING_H

#include <base/base.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

void error(const char *msg);
void print_bytes(uchar *data, size_t len);
void get_ct_tag(uchar *ct, int *ct_len, uchar *tag, uchar *buffer, size_t len);
uchar * concat_uc_str(const uchar *arr1, const size_t len1, const uchar *arr2, const size_t len2);
int cmp_uc_str(const uchar *arr1, const uchar *arr2, const size_t len);
char * concatString(const char *str1, const char *str2);
void hexStringToBytes(const char *str, uchar *bytes, size_t length);
void insert_header_len(uchar *header, uint32_t len, int start, int end);
ssize_t send_response(int sockfd, const uchar* data, size_t data_len);
void send_backend_response(int sockfd, const char *filename, const char *filetype);
void read_file(uchar **data, uint64_t *len, const char *filename, int type);
char * getFileType(char *filename);
void parseRequest(int sockfd, char *buffer);

#endif