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

struct libnet_ethernet_hdr *eh;
struct libnet_ipv4_hdr *ih;
struct libnet_tcp_hdr *th;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *adhandle;
	struct bpf_program fcode;
	char packet_filter[] = "ip and tcp";
	char errbuf[PCAP_ERRBUF_SIZE];
	int i, inum;
	bpf_u_int32 ip_addr;
	bpf_u_int32 subnet;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs_ex() Error : %s\n", errbuf);
		return -1;
	}

	for (i = 0, d = alldevs; d != NULL; d = d->next, i++) {
		printf("Number : %d Name : %s",i,d->name);
		if (d->description) {
			printf(" Description : %s\n", d->description);
		}
		else {
			printf(" Not Description\n");
		}
	}

	printf("Select Number : ");
	scanf("%d", &inum);

	if (inum < 0 || inum > i - 1) {
		fprintf(stderr, "Out of Range...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (i = 0, d = alldevs; i < inum; i++, d = d->next);

	if ((adhandle=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open() Error : %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "Only ethernet...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_lookupnet(d->name, &ip_addr, &subnet, errbuf) == -1) {
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

	printf("Listening on %s...\n", d->name);
	pcap_freealldevs(alldevs);
	
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	static int i = 0;
	int k;
	u_int ip_len;
	u_short sport, dport;
	u_int psize = header->len;
	eh = (struct libnet_ethernet_hdr *)pkt_data;
	ih = (struct libnet_ipv4_hdr *)(pkt_data + 14);
	ip_len = (ih->ip_hl) * 4;
	th = (struct libnet_tcp_hdr *)((u_char *)ih + ip_len);

	sport = ntohs(th->th_sport);
	dport = ntohs(th->th_dport);

	printf("Packet Number : %d\n", i++);
	printf("Packet Size : %d\n", psize);
	
	printf("MAC dst : ");
	for (k = 0; k < ETHER_ADDR_LEN; k++) {
		if (k != ETHER_ADDR_LEN - 1) {
			printf("%02X:", eh->ether_dhost[k]);
		}
		else {
			printf("%02X\n", eh->ether_dhost[k]);
		}
	}
	printf("MAC src : ");
	for (k = 0; k < ETHER_ADDR_LEN; k++) {
		if (k != ETHER_ADDR_LEN - 1) {
			printf("%02X:", eh->ether_shost[k]);
		}
		else {
			printf("%02X\n", eh->ether_shost[k]);
		}
	}

	printf("IP dst : %s\n",inet_ntoa(ih->ip_dst));
	printf("IP src : %s\n", inet_ntoa(ih->ip_src));
	printf("Dst Port : %d\n", dport);
	printf("Src Port : %d\n", sport);

}

