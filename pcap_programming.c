#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>    
#include <stdlib.h>    
#include <unistd.h>    
#include <errno.h>     
#include <limits.h>    

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* ethernet_header = (struct ether_header*)packet;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

    printf("Ethernet Header:\n");
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2],
           ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2],
           ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    printf("\nIP Header:\n");
    printf("\tSource IP: %s\n", source_ip);
    printf("\tDestination IP: %s\n\n", dest_ip);

    printf("TCP Header:\n");
    printf("\tSource Port: %d\n", ntohs(tcp_header->th_sport));
    printf("\tDestination Port: %d\n", ntohs(tcp_header->th_dport));

    int packet_length = pkthdr->len;
    printf("\nPacket Length: %d bytes\n", packet_length);

    int tcp_data_length = packet_length - sizeof(struct ether_header) - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);
    if (tcp_data_length > 0) {
        printf("TCP Message Data:\n");
        const u_char* tcp_data = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
        int max_printable = tcp_data_length < 100 ? tcp_data_length : 100;
        for (int i = 0; i < max_printable; i++) {
            printf("%02x ", tcp_data[i]);
        }
        printf("\n");
    }
    printf("=======================\n\n");
}

int main() {
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    struct pcap_if* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "장치를 찾을 수 없습니다: %s\n", errbuf);
        return 1;
    }
    dev = alldevs->name;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "핸들을 열 수 없습니다: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "패킷 캡처 중 오류 발생: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}

