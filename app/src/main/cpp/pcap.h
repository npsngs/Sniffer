#ifndef SNIFFER_PCAP_H
#define SNIFFER_PCAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

extern void start_rec(const char *path);
extern char* joinStr(const char *s1, const char *s2);

#ifdef __cplusplus
}
#endif

#endif //SNIFFER_PCAP_H
