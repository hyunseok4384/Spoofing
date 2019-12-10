#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>

#ifdef WIN32
	#ifdef _WINSOCK2API_
		#include <WinSock2.h>
		#include <windows.h>
	#else
		#include <winsock.h>
	#endif
#elif defined __gnu_linux__
	#include <sys/socket.h>
	#include <netinet/in.h>
#endif

int main() {
	struct libnet_arp_hdr *arp_hd = malloc(sizeof(struct libnet_arp_hdr));
	struct libnet_ethernet_hdr *ether_hd = malloc(sizeof(struct libnet_ethernet_hdr));
	struct libnet_ether_addr *sender_mac = malloc(sizeof(struct libnet_ether_addr));
	struct libnet_ether_addr *target_mac = malloc(sizeof(struct libnet_ether_addr));
	struct bpf_program fcode;
	struct pcap_pkthdr *pkt_hdr;
	struct in_addr *sender_addr = malloc(sizeof(struct in_addr));
	struct in_addr *target_addr = malloc(sizeof(struct in_addr));
	u_char *pkt_data;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *adhandle;
	bpf_u_int32 ipaddr, subnet;
	int res, i;
	int cnt = 0;
	int inum=0;
	const char packet_filter[] = "arp";
	u_char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs_ex() Error : %s\n", errbuf);
		return -1;
	}
	for (i = 0, d = alldevs; d != NULL; d = d->next, i++) {
		printf("Number : %d Name : %s", i, d->name);
		if (d->description) {
			printf(" Description : %s\n", d->description);
		}
		else {
			printf(" Not Description\n");
		}
	}

	printf("Select Number : ");
	scanf("%d", &inum);

	if (inum<0 || inum>i-1) {
		printf("Out of Range...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (i = 0, d = alldevs; i < inum; i++, d = d->next);

	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open() Error : %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_lookupnet(d->name, &ipaddr, &subnet,errbuf) < 0) {
		fprintf(stderr, "pcap_lookupnet() Error : %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, subnet) < 0) {
		fprintf(stderr, "pcap_compile() Error...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "pcap_setfilter() Error...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs);
	printf("Listening on %s...\n", d->description);

	while ((res = pcap_next_ex(adhandle, &pkt_hdr, &pkt_data)) >= 0) {
		if (res == 0) {
			continue;
		}
		else {
			ether_hd = (struct libnet_ethernet_hdr *)pkt_data;
			arp_hd = (struct libnet_arp_hdr *)((char *)pkt_data + 14);

			sender_mac = (struct libnet_ether_addr *)((char *)(arp_hd)+8);
			sender_addr = (struct in_addr *)((char *)(sender_mac) + 6);
			target_mac = (struct libnet_ether_addr *)((char *)(sender_addr) + 4);
			target_addr = (struct in_addr *)((char *)(target_mac) + 6);

			printf("--------------------------------------\n");
			printf("Packet Number : %d\n", cnt++);
			printf("/////////////////////////////////////\n");
			printf("Ethernet_Header\n");
			
			printf("Dest Mac Address : ");
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				if (i != ETHER_ADDR_LEN - 1) {
					printf("%02X:", ether_hd->ether_dhost[i]);
				}
				else {
					printf("%02X\n", ether_hd->ether_dhost[i]);
				}
			}

			printf("Src Mac Address : ");
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				if (i != ETHER_ADDR_LEN - 1) {
					printf("%02X:", ether_hd->ether_shost[i]);
				}
				else {
					printf("%02X\n", ether_hd->ether_shost[i]);
				}
			}
			printf("Type : 0x%04X\n", ntohs(ether_hd->ether_type));
			printf("/////////////////////////////////////\n");
			printf("Arp_Header\n");
			if ((ntohs(arp_hd->ar_hrd)) == ARPHRD_ETHER) {
				printf("Hardware Type : Ethernet\n");
			}
			else {
				printf("%d\n", ntohs(arp_hd->ar_hrd));
			}
			printf("Protocol Type : 0x%04X\n", ntohs(arp_hd->ar_pro));
			printf("Hardware Size : %x\n", arp_hd->ar_hln);
			printf("Protocol Size : %x\n", arp_hd->ar_pln);
			printf("Opcode : %d", ntohs(arp_hd->ar_op));
			if (ntohs(arp_hd->ar_op) == 1) {
				printf(" (REQUEST)\n");
			}
			else {
				printf(" (REPLY)\n");
			}

			printf("Sender Mac Address : ");
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				if (i != ETHER_ADDR_LEN - 1) {
					printf("%02X:", sender_mac->ether_addr_octet[i]);
				}
				else {
					printf("%02X\n", sender_mac->ether_addr_octet[i]);
				}
			}

			printf("Sender IP Address : %s\n", inet_ntoa(*sender_addr));

			printf("Target Mac Address : ");
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				if (i != ETHER_ADDR_LEN - 1) {
					printf("%02X:", target_mac->ether_addr_octet[i]);
				}
				else {
					printf("%02X\n", target_mac->ether_addr_octet[i]);
				}
			}

			printf("Target IP Address : %s\n", inet_ntoa(*target_addr));
			printf("/////////////////////////////////////\n");
			printf("---------------------------------------------");


		}
		
	}
}

