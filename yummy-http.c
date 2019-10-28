#include "pcap.h"
#include <stdio.h>

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

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

typedef struct ip_header {
	u_char vih;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flag;
	u_char ttl;
	u_char protocol;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
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

typedef struct ether_header {
	mac_address dmac;
	mac_address smac;
	u_short type;
}ether_header;

#define LINE_LEN 16
#define SOURCE "D:\\http-packet\\httpGet.pcap"

int main(int argc, char **argv) {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

	/*
	if (argc != 2) {
		printf("usage : %s filename", argv[0]);
		return -1;
	}
	*/

	if (pcap_createsrcstr(source, PCAP_SRC_FILE, NULL, NULL, SOURCE, errbuf) != 0) {
		fprintf(stderr, "Error creating a source string\n");
		return -1;
	}

	if ((fp = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "Unable to open the file %s\n", source);
		return -1;
	}

	pcap_loop(fp, 0, packet_handler, NULL);
	return 0;
	
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	ether_header *eh;
	ip_header *ih;
	tcp_header *th;
	static int i = 0;
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
	printf("MAC src : %02X%02X:%02X%02X:%02X%02X\n",
		eh->smac.byte1,
		eh->smac.byte2,
		eh->smac.byte3,
		eh->smac.byte4,
		eh->smac.byte5,
		eh->smac.byte6);
	printf("MAC dest : %02X%02X:%02X%02X:%02X%02X\n",
		eh->dmac.byte1,
		eh->dmac.byte2,
		eh->dmac.byte3,
		eh->dmac.byte4,
		eh->dmac.byte5,
		eh->dmac.byte6);
	printf("IP src : %d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4);
	printf("IP dest : %d.%d.%d.%d\n",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	printf("Src port : %d\nDst port : %d\n\n", sport, dport);
}