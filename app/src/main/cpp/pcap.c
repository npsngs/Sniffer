#include "pcap.h"

/*char *lookupdev(char * errbuf) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        snprintf(errbuf, ERRBUF_SIZE, "socket: %d", errno);
        return (char *)-1;
    }
    size_t buf_size = 8192;
    char *buf = NULL;
    struct ifconf ifc;
    struct ifreq *ifrp, *ifend, *ifnext;

    for (;;) {
        buf = malloc(buf_size);
        if (buf == NULL) {
            snprintf(errbuf, ERRBUF_SIZE, "malloc: %d", errno);
            close(fd);
            return (char *) (-1);
        }

        ifc.ifc_len = (int) buf_size;
        ifc.ifc_buf = buf;
        memset(buf, 0, buf_size);

        if (ioctl(fd, SIOCGIFCONF, (char *) &ifc) < 0 && errno != EINVAL) {
            snprintf(errbuf, ERRBUF_SIZE, "SIOCGIFCONF: %d", errno);
            close(fd);
            free(buf);
            return (char *) (-1);
        }

        if (ifc.ifc_len < buf_size &&
            (buf_size - ifc.ifc_len) > sizeof(ifrp->ifr_name) + MAX_SA_LEN)
            break;
        free(buf);
        buf_size *= 2;
    }


    ifrp = (struct ifreq *)buf;
    ifend = (struct ifreq *)(buf + ifc.ifc_len);
    int n = 0;
    for (; ifrp < ifend; ifrp = ifnext) {*/
        /*  *//*
         * XXX - what if this isn't an IPv4 address?  Can
         * we still get the netmask, etc. with ioctls on
         * an IPv4 socket?
         *
         * The answer is probably platform-dependent, and
         * if the answer is "no" on more than one platform,
         * the way you work around it is probably platform-
         * dependent as well.
         *//*
        n = sizeof (struct sockaddr) + sizeof(ifrp->ifr_name);
        if (n < sizeof(*ifrp))
            ifnext = ifrp + 1;
        else
            ifnext = (struct ifreq *)((char *)ifrp + n);

        *//*
         * XXX - The 32-bit compatibility layer for Linux on IA-64
         * is slightly broken. It correctly converts the structures
         * to and from kernel land from 64 bit to 32 bit but
         * doesn't update ifc.ifc_len, leaving it larger than the
         * amount really used. This means we read off the end
         * of the buffer and encounter an interface with an
         * "empty" name. Since this is highly unlikely to ever
         * occur in a valid case we can just finish looking for
         * interfaces if we see an empty name.
         *//*
        if (!(*ifrp->ifr_name))
            break;

        *//*
         * Skip entries that begin with "dummy".
         * XXX - what are these?  Is this Linux-specific?
         * Are there platforms on which we shouldn't do this?
         *//*
        if (strncmp(ifrp->ifr_name, "dummy", 5) == 0)
            continue;

        *//*
         * Can we capture on this device?
         *//*
        if (!(*check_usable)(ifrp->ifr_name)) {
            *//*
             * No.
             *//*
            continue;
        }

        *//*
         * Get the flags for this interface.
         *//*
        strncpy(ifrflags.ifr_name, ifrp->ifr_name,
                sizeof(ifrflags.ifr_name));
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
            if (errno == ENXIO)
                continue;
            (void)pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
                                "SIOCGIFFLAGS: %.*s: %s",
                                (int)sizeof(ifrflags.ifr_name),
                                ifrflags.ifr_name,
                                pcap_strerror(errno));
            ret = -1;
            break;
        }

        *//*
         * Get the netmask for this address on this interface.
         *//*
        strncpy(ifrnetmask.ifr_name, ifrp->ifr_name,
                sizeof(ifrnetmask.ifr_name));
        memcpy(&ifrnetmask.ifr_addr, &ifrp->ifr_addr,
               sizeof(ifrnetmask.ifr_addr));
        if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifrnetmask) < 0) {
            if (errno == EADDRNOTAVAIL) {
                *//*
                 * Not available.
                 *//*
                netmask = NULL;
                netmask_size = 0;
            } else {
                (void)pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
                                    "SIOCGIFNETMASK: %.*s: %s",
                                    (int)sizeof(ifrnetmask.ifr_name),
                                    ifrnetmask.ifr_name,
                                    pcap_strerror(errno));
                ret = -1;
                break;
            }
        } else {
            netmask = &ifrnetmask.ifr_addr;
            netmask_size = SA_LEN(netmask);
        }

        *//*
         * Get the broadcast address for this address on this
         * interface (if any).
         *//*
        if (ifrflags.ifr_flags & IFF_BROADCAST) {
            strncpy(ifrbroadaddr.ifr_name, ifrp->ifr_name,
                    sizeof(ifrbroadaddr.ifr_name));
            memcpy(&ifrbroadaddr.ifr_addr, &ifrp->ifr_addr,
                   sizeof(ifrbroadaddr.ifr_addr));
            if (ioctl(fd, SIOCGIFBRDADDR,
                      (char *)&ifrbroadaddr) < 0) {
                if (errno == EADDRNOTAVAIL) {
                    *//*
                     * Not available.
                     *//*
                    broadaddr = NULL;
                    broadaddr_size = 0;
                } else {
                    (void)pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
                                        "SIOCGIFBRDADDR: %.*s: %s",
                                        (int)sizeof(ifrbroadaddr.ifr_name),
                                        ifrbroadaddr.ifr_name,
                                        pcap_strerror(errno));
                    ret = -1;
                    break;
                }
            } else {
                broadaddr = &ifrbroadaddr.ifr_broadaddr;
                broadaddr_size = SA_LEN(broadaddr);
            }
        } else {
            *//*
             * Not a broadcast interface, so no broadcast
             * address.
             *//*
            broadaddr = NULL;
            broadaddr_size = 0;
        }

        *//*
         * Get the destination address for this address on this
         * interface (if any).
         *//*
        if (ifrflags.ifr_flags & IFF_POINTOPOINT) {
            strncpy(ifrdstaddr.ifr_name, ifrp->ifr_name,
                    sizeof(ifrdstaddr.ifr_name));
            memcpy(&ifrdstaddr.ifr_addr, &ifrp->ifr_addr,
                   sizeof(ifrdstaddr.ifr_addr));
            if (ioctl(fd, SIOCGIFDSTADDR,
                      (char *)&ifrdstaddr) < 0) {
                if (errno == EADDRNOTAVAIL) {
                    *//*
                     * Not available.
                     *//*
                    dstaddr = NULL;
                    dstaddr_size = 0;
                } else {
                    (void)pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
                                        "SIOCGIFDSTADDR: %.*s: %s",
                                        (int)sizeof(ifrdstaddr.ifr_name),
                                        ifrdstaddr.ifr_name,
                                        pcap_strerror(errno));
                    ret = -1;
                    break;
                }
            } else {
                dstaddr = &ifrdstaddr.ifr_dstaddr;
                dstaddr_size = SA_LEN(dstaddr);
            }
        } else {
            *//*
             * Not a point-to-point interface, so no destination
             * address.
             *//*
            dstaddr = NULL;
            dstaddr_size = 0;
        }

#if defined (HAVE_SOLARIS) || defined (HAVE_HPUX10_20_OR_LATER)
        *//*
		 * If this entry has a colon followed by a number at
		 * the end, it's a logical interface.  Those are just
		 * the way you assign multiple IP addresses to a real
		 * interface, so an entry for a logical interface should
		 * be treated like the entry for the real interface;
		 * we do that by stripping off the ":" and the number.
		 *//*
		p = strchr(ifrp->ifr_name, ':');
		if (p != NULL) {
			*//*
			 * We have a ":"; is it followed by a number?
			 *//*
			q = p + 1;
			while (isdigit((unsigned char)*q))
				q++;
			if (*q == '\0') {
				*//*
				 * All digits after the ":" until the end.
				 * Strip off the ":" and everything after
				 * it.
				 *//*
				*p = '\0';
			}
		}
#endif

        *//*
         * Add information for this address to the list.
         *//*
        if (add_addr_to_iflist(&devlist, ifrp->ifr_name,
                               if_flags_to_pcap_flags(ifrp->ifr_name, ifrflags.ifr_flags),
                               &ifrp->ifr_addr, SA_LEN(&ifrp->ifr_addr),
                               netmask, netmask_size, broadaddr, broadaddr_size,
                               dstaddr, dstaddr_size, errbuf) < 0) {
            ret = -1;
            break;
        }
    }
    free(buf);
    (void)close(fd);

    if (ret == -1) {
        *//*
         * We had an error; free the list we've been constructing.
         *//*
        if (devlist != NULL) {
            pcap_freealldevs(devlist);
            devlist = NULL;
        }
    }

    *alldevsp = devlist;
    return (ret);*/
/*    }
    return NULL;
}*/

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
