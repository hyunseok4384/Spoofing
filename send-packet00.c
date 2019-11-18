#include "pcap.h"
#include "libnet.h"

#ifdef WIN32
	#ifdef _WINSOCK2API_
		#include <winsock2.h>
		#include <windows.h>
	#else
		#include <winsock.h>
	#endif
#elif defined __gnu_linux__
	#include <sys/socket.h>
	#include <netinet/in.h>
#endif

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *adhandle;
	int i, inum;
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet[100];
	struct libnet_ethernet_hdr *eh = malloc(sizeof(struct libnet_ethernet_hdr));

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
	if (inum<0 || inum>i - 1) {
		fprintf(stderr, "Out of Range...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (i = 0, d = alldevs; i < inum; i++, d = d->next);

	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == -1) {
		fprintf(stderr, "pcap_open() Error : %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}
	pcap_freealldevs(alldevs);

	eh->ether_dhost[0] = 0xFF;
	eh->ether_dhost[1] = 0xFF;
	eh->ether_dhost[2] = 0xFF;
	eh->ether_dhost[3] = 0xFF;
	eh->ether_dhost[4] = 0xFF;
	eh->ether_dhost[5] = 0xFF;

	eh->ether_shost[6] = 0x11;
	eh->ether_shost[7] = 0x22;
	eh->ether_shost[8] = 0x33;
	eh->ether_shost[9] = 0x44;
	eh->ether_shost[10] = 0x55;
	eh->ether_shost[11] = 0x66;

	eh->ether_type = ETHERTYPE_ARP;

	if (pcap_sendpacket(adhandle, (u_char *)eh, sizeof(struct libnet_ethernet_hdr)) != 0)
	{
		fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	else {
		printf("Success Send Packet\n");
		return 0;
	}
}