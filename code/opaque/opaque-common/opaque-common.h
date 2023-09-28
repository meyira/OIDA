#ifndef OPAQUE_COMMON_H
#define OPAQUE_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

uint64_t rdtsc();
void debug_print(const char *name, const unsigned char *m, size_t m_len);

int setup_socket_s(int *serversocket, uint16_t port);
void setup_socket_c(int *csocket, const char *hostname, uint16_t port);
int read_len(int socket, unsigned char *buf, ssize_t length, const char *info);

#endif
