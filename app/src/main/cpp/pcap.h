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

typedef struct {
    int32_t startPos;
    int32_t len;
}Message;

/**
 * 建立双线程， 一个负责监听网卡数据并过滤，一个线程负责给客户应用程序新数据包通知
 */
extern void init(const char *pid);


/**
 * 给客户应用程序新数据包通知
 */
extern void sendMessage(Message *msg);

/**
 * 监听网卡数据并过滤
 */
extern void start_rec(const char *path);
extern char* joinStr(const char *s1, const char *s2);

#ifdef __cplusplus
}
#endif

#endif //SNIFFER_PCAP_H
