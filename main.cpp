#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define IPv4 0x0800
#define IPv6 0x86dd
#define ARP 0x0806
#define RARP 0x0835

void print_MAC_address(u_char * MAC_address) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", MAC_address[0], MAC_address[1], MAC_address[2], MAC_address[3], MAC_address[4], MAC_address[5]);
}

void print_Ethernet_type(u_int16_t type) {
	printf("0x%04x", type);
	if(type == IPv4) {
		printf(" (IPv4)");
	}
	else if(type == IPv6) {
		printf(" (IPv6)");
	}
	else if(type == ARP) {
		printf(" (ARP)");
	}
	else if(type == RARP) {
		printf(" (RARP)");
	}
	printf("\n");
}

int main(int argc, char * argv[]) {
	if(argc != 2) {
		printf("Please input : pcap_test <interface_name>\n");
		exit(0);
	}

	struct ether_header * eth_header;
	struct ip * ip_header;
	struct tcphdr * tcp_header;

	int dataSize;
	char * target_interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t * pcd = pcap_open_live(target_interface, BUFSIZ, 1, 1000, errbuf);
	if(pcd == NULL) {
		fprintf(stderr, "Not valid Interface %s : %s\n", target_interface, errbuf);
		exit(0);
	}

	while(1) {
		struct pcap_pkthdr * header;
		const u_char * packet;
		int response = pcap_next_ex(pcd, &header, &packet);
		if(response == 1) {
			continue;
		}
		else if(response == -1 || response == -2) {
			break;
		}
		eth_header = (struct ether_header *)packet;
		printf("============================================================\n");
		printf("Ethernet Source MAC : ");
		print_MAC_address(eth_header->ether_shost);
		printf("Ethernet Destination MAC : ");
		print_MAC_address(eth_header->ether_dhost);
		printf("Ethernet Type : ");
		print_Ethernet_type(htons(eth_header->ether_type));
		packet += sizeof(struct ether_header);
		if(htons(eth_header->ether_type) == IPv4) {
			ip_header = (struct ip *)packet;
			printf("\n");
			printf("IPv4 Source Address : ");
			printf("%s\n", inet_ntoa(ip_header->ip_src));
			printf("IPv4 Destination Address : ");
			printf("%s\n", inet_ntoa(ip_header->ip_dst));
			packet += (ip_header->ip_hl) * 4;
			if(ip_header->ip_p == 6) {
				tcp_header = (struct tcphdr *)packet;
				printf("\n");
				printf("TCP Source Port : ");
				printf("%hu\n", htons(tcp_header->th_sport));
				printf("TCP Destination Port : ");
				printf("%hu\n", htons(tcp_header->th_dport));
				packet += (tcp_header->th_off) * 4;

				dataSize = ((int)(htons(ip_header->ip_len)) - ((ip_header->ip_hl) * 4) + ((tcp_header->th_off) * 4));
				if (dataSize != 0) {
					printf("\n");
					printf("Data(hex) : ");
					for (int i = 0; i < dataSize; i++) {
						printf("%02x ", packet[i]);
					}
					printf("\n");
				}
			}
		}	

	}
	pcap_close(pcd);
	return 0;
}
