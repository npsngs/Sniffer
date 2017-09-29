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
    struct tcphdr *tcph;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket");
        return;
    }

    while (1) {
        //注意：在这之前我没有调用bind函数，原因是什么呢？
        n = recvfrom(sock, ptr,PAGE_SIZE,0,NULL,NULL);

        if(n < 0){
            return;
        }
        //接收到的数据帧头6字节是目的MAC地址，紧接着6字节是源MAC地址。
        eth=(struct ethhdr*)ptr;

        __be16 proto = htons(eth->h_proto);
        if(proto == 0x0800){
            printf("=====================================\n");
            printf("%d bytes read\n",n);
            printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
            printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
            printf("type:0x%04x\n",proto);

            iph=(struct iphdr*)(ptr+sizeof(struct ethhdr));
            printf("ip pro:0x%02x\n",iph->protocol);
            if(iph->version ==4 && iph->ihl == 5 && iph->protocol == IPPROTO_TCP){
                struct in_addr src, dst;
                src.s_addr = iph->saddr;
                dst.s_addr = iph->daddr;

                printf("Source host:%s\n",inet_ntoa(src));
                printf("Dest host:%s\n",inet_ntoa(dst));

                tcph = (struct tcphdr*)(ptr+sizeof(struct ethhdr)+sizeof(struct iphdr));
                printf("source:%d\n",tcph->source);
                printf("dest:%d\n",tcph->dest);
                printf("seq:%d\n",tcph->seq);
                printf("ack_seq:%d\n",tcph->ack_seq);

                char *s = (char *)(ptr + sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
                printf(s);
            }
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
