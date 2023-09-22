#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr iph_sourceip;
    struct  in_addr iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) { // IP 타입인 경우
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        if (ip->iph_protocol == IPPROTO_TCP) { // TCP 프로토콜인 경우
            printf("Ethernet Header:\n");
            printf("    Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("    Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("IP Header:\n");
            printf("    Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("    Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
            printf("TCP Header:\n");
            printf("    Source Port: %u\n", ntohs(tcp->tcp_sport));
            printf("    Destination Port: %u\n", ntohs(tcp->tcp_dport));

            // Print message (for a certain length)
            int message_length = header->len - (sizeof(struct ethheader) + ip->iph_ihl * 4 + TH_OFF(tcp) * 4);
            if (message_length > 0) {
                printf("Message (first 20 bytes): ");
                for (int i = 0; i < message_length && i < 20; ++i) {
                    printf("%02x ", packet[sizeof(struct ethheader) + ip->iph_ihl * 4 + TH_OFF(tcp) * 4 + i]);
                }
                printf("\n");
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}

