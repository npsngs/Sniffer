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

/**
 * 监听网卡数据并过滤
 */
extern void start_rec(const char *path);
extern char* joinStr(const char *s1, const char *s2);
extern int ip2name(char *out_buf, const struct in_addr *addr, int maxlen);
extern void ipstr2name(char *out_buf, const char *ip, int maxlen);
#ifdef __cplusplus
}
#endif

#endif //SNIFFER_PCAP_H
