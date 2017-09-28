#include "pcap.h"


void start_rec(const char* path) {
    char *ferr = joinStr(path, "/stderr.txt");
    freopen(ferr,"a",stderr);
    free(ferr);

    size_t  map_size = PAGE_SIZE*64;
    int fd = open("/data/local/mmap_f", O_CREAT|O_RDWR, 0777);
    if(fd < 0){
        perror("open");
    }
    lseek(fd, PAGE_SIZE*70, SEEK_SET);
    write(fd, "a", 1);

    void* ptr = mmap(NULL, map_size, PROT_READ|PROT_WRITE|PROT_GROWSDOWN, MAP_SHARED, fd, SEEK_SET);
    void* src_ptr = ptr;
    void* limit_ptr = ptr+PAGE_SIZE;
    printf("mmap_ptr:0x%x\n", ptr);
    if(ptr == MAP_FAILED){
        perror("mmap");
    }

    int sock;
    ssize_t n;
    struct ethhdr *eth;
    struct iphdr *iph;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket");
        return;
    }

    while (1) {
        printf("=====================================\n");
        //注意：在这之前我没有调用bind函数，原因是什么呢？
        n = recvfrom(sock, ptr,PAGE_SIZE,0,NULL,NULL);
        printf("%d bytes read\n",n);
        if(n < 0){
            return;
        }
        //接收到的数据帧头6字节是目的MAC地址，紧接着6字节是源MAC地址。
        eth=(struct ethhdr*)ptr;
        printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
        printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

        iph=(struct iphdr*)(ptr+sizeof(struct ethhdr));
        //我们只对IPV4且没有选项字段的IPv4报文感兴趣
        if(iph->version ==4 && iph->ihl == 5){
            struct in_addr src, dst;
            src.s_addr = iph->saddr;
            dst.s_addr = iph->daddr;

            printf("Source host:%s\n",inet_ntoa(src));
            printf("Dest host:%s\n",inet_ntoa(dst));
        }

        ptr += n;
        if(ptr > limit_ptr){
            ptr = src_ptr;
        }
    }
}

char* joinStr(const char *s1, const char *s2) {
    char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    if (result == NULL) exit (1);

    strcpy(result, s1);
    strcat(result, s2);

    return result;
}

void init(const char *pid) {
    
}

void sendMessage(Message *msg) {

}
