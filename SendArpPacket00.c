#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	struct in_addr *sender_addr = malloc(sizeof(struct in_addr));
	struct in_addr *target_addr = malloc(sizeof(struct in_addr));
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *adhandle;
	int i;
	int cnt = 0;
	int inum = 0;
	u_char errbuf[PCAP_ERRBUF_SIZE];
	u_char ArpPacket[sizeof(struct libnet_arp_hdr)+ sizeof(struct libnet_ethernet_hdr)+ sizeof(struct libnet_ether_addr)+ sizeof(struct libnet_ether_addr)+ sizeof(struct in_addr)+ sizeof(struct in_addr)];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs_ex() Error : %s\n", errbuf);
		return -1;
	}

	for (i = 0, d = alldevs; d != NULL; i++, d = d->next) {
		printf("Number : %d Name : %s ", i, d->name);
		if (d->description) {
			printf(" Description : %s\n", d->description);
		}
		else {
			printf(" Not Description\n");
		}
	}

	printf("Select Number : ");
	scanf("%d", &inum);

	if (inum<0 || inum>i - 1) {
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

	pcap_freealldevs(alldevs);

	
	for (i = 0; i < 6; i++) {
		ether_hd->ether_dhost[i] = 0xff;
	}
	/*
	ether_hd->ether_dhost[0] = 0xac;
	ether_hd->ether_dhost[1] = 0x2b;
	ether_hd->ether_dhost[2] = 0x6e;
	ether_hd->ether_dhost[3] = 0x7c;
	ether_hd->ether_dhost[4] = 0x10;
	ether_hd->ether_dhost[5] = 0x32;
	*/

	ether_hd->ether_shost[0] = 0x2c;
	ether_hd->ether_shost[1] = 0x6f;
	ether_hd->ether_shost[2] = 0xc9;
	ether_hd->ether_shost[3] = 0x1c;
	ether_hd->ether_shost[4] = 0xb4;
	ether_hd->ether_shost[5] = 0xc7;

	ether_hd->ether_type = htons(ETHERTYPE_ARP);

	
	arp_hd->ar_hrd = htons(ARPHRD_ETHER);
	arp_hd->ar_pro = htons(0x0800);
	arp_hd->ar_hln = 0x06;
	arp_hd->ar_pln = 0x04;
	arp_hd->ar_op = htons(ARPOP_REQUEST);

	sender_mac->ether_addr_octet[0] = 0x2c;
	sender_mac->ether_addr_octet[1] = 0x6f;
	sender_mac->ether_addr_octet[2] = 0xc9;
	sender_mac->ether_addr_octet[3] = 0x1c;
	sender_mac->ether_addr_octet[4] = 0xb4;
	sender_mac->ether_addr_octet[5] = 0xc7;

	sender_addr->S_un.S_addr = inet_addr("172.20.10.1");
	
	/*
	for (i = 0; i < 6; i++) {
		target_mac->ether_addr_octet[i] = 0x00;
	}
	*/
	target_mac->ether_addr_octet[0] = 0xac;
	target_mac->ether_addr_octet[1] = 0x2b;
	target_mac->ether_addr_octet[2] = 0x6e;
	target_mac->ether_addr_octet[3] = 0x7c;
	target_mac->ether_addr_octet[4] = 0x10;
	target_mac->ether_addr_octet[5] = 0x32;
	
	target_addr->S_un.S_addr = inet_addr("172.20.10.3");

	memcpy(ArpPacket, ether_hd, sizeof(struct libnet_ethernet_hdr));
	memcpy(ArpPacket + 14, arp_hd, sizeof(struct libnet_arp_hdr));
	memcpy(ArpPacket + 14 + 8, sender_mac, sizeof(struct libnet_ether_addr));
	memcpy(ArpPacket + 14 + 8 + 6,&sender_addr->S_un.S_addr, sizeof(struct in_addr));
	memcpy(ArpPacket + 14 + 8 + 6 + 4, target_mac, sizeof(struct libnet_ether_addr));
	memcpy(ArpPacket + 14 + 8 + 6 + 4 + 6, &target_addr->S_un.S_addr, sizeof(struct in_addr));
	
	
	
	if (pcap_sendpacket(adhandle, ArpPacket, sizeof(struct libnet_ethernet_hdr)+
		sizeof(struct libnet_arp_hdr)+ sizeof(struct libnet_ether_addr)+ sizeof(4)+
		sizeof(struct libnet_ether_addr)+ sizeof(4)) != 0)
	{
		fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	else {
		printf("Success Send Packet\n");
		return 0;
	}
	
	


}