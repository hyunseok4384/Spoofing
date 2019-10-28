#include "pcap.h"

#ifdef WIN32
	#ifdef _WINSOCK2API_
		#include <windows.h>
		#include <winsock2.h>
	#else
		#include <winsock.h>
	#endif
#elif defined __gnu_linux__
	#include <sys/socket.h>
	#include <netinet/in.h>
#endif

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

typedef struct ip_header {
	u_char vih;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flag;
	u_char ttl;
	u_char protocol;
	u_short crc;
	u_char saddr[4];
	u_char daddr[4];
	u_int opt;
}ip_header;

typedef struct tcp_header {
	u_short sport;
	u_short dport;
	u_int seqnum;
	u_int acknum;
	u_char offr;
	u_char flag;
	u_short window;
	u_short crc;
	u_short pointer;
	u_int opt;
}tcp_header;

typedef struct ether_header{
	u_char dmac[6];
	u_char smac[6];
	u_short type;
}ether_header;

int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *adhandle;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "ip and tcp";
	int i, inum;
	bpf_u_int32 netmask;
	bpf_u_int32 ipaddr;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs_ex() Error : %s\n", errbuf);
		return -1;
	}
	for (d = alldevs, i = 0; d != NULL; d = d->next, i++) {
		printf("Number : %d Name : %s", i, d->name);
		if (d->description) {
			printf(" Description : %s\n",d->description);
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

	for (d = alldevs, i = 0; i < inum; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf)) == NULL) {
		fprintf(stderr, "pcap_open() Error : %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "Only Ethernet...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_lookupnet(d->name, &ipaddr, &netmask,errbuf) == -1) {
		fprintf(stderr,"pcap_lookup() Fail...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_compile(adhandle, &fcode, packet_filter, 1,netmask) < 0) {
		fprintf(stderr, "pcap_compile() Error...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "pcap_setfilter() Error...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("listening on %s...\n", d->name);
	pcap_freealldevs(alldevs);
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	ether_header *eh;
	ip_header *ih;
	tcp_header *th;
	static int i = 0;
	int j;
	u_int ip_len;
	u_short sport, dport;
	u_int psize = header->len;

	eh = (ether_header *)pkt_data;
	ih = (ip_header *)(pkt_data + 14);
	ip_len = (ih->vih & 0xf) * 4;
	th = (tcp_header *)((u_char *)ih + ip_len);

	sport = ntohs(th->sport);
	dport = ntohs(th->dport);

	printf("Packet No .%d\n", i++);
	printf("Packet Size : %d bytes\n", psize);
	printf("MAC src : ");
	for (j = 0; j < 6; j++) {
		if (j != 5) {
			printf("%02X:",eh->smac[i]);
		}
		else {
			printf("%02X\n", eh->smac[i]);
		}
	}

	printf("MAC dest : ");
	for (j = 0; j < 6; j++) {
		if (j != 5) {
			printf("%02X:", eh->dmac[j]);
		}
		else {
			printf("%02X\n", eh->dmac[j]);
		}
	}
	
	printf("IP src : ");
	for (j = 0; j < 4; j++) {
		if (j != 3) {
			printf("%d:", ih->saddr[j]);
		}
		else {
			printf("%d\n", ih->saddr[j]);
		}
	}

	printf("IP dest : ");
	for (j = 0; j < 4; j++) {
		if (j != 3) {
			printf("%d:", ih->daddr[j]);
		}
		else {
			printf("%d\n", ih->daddr[j]);
		}
	}
	printf("Src port : %d\nDst port : %d\n\n", sport, dport);
}
