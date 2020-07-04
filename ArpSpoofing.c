#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <process.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")

#ifdef WIN32
	#ifdef _WINSOCK2API_
		#include <WinSock2.h>
		#include <windows.h>
	#else
		#include <winsock.h>
		#include <windows.h>
	#endif
#elif defined __gnu_linux__
	#include <sys/socket.h>
	#include <netinet/in.h>
#endif

struct libnet_ether_addr *router_mac;
struct libnet_ether_addr *target_mac;
struct libnet_ether_addr *my_mac;
struct in_addr *router_addr;
struct in_addr *target_addr;
struct in_addr *my_addr;

pcap_if_t *alldevs;
pcap_if_t *d;
pcap_t *adhandle;

int FindGatewayMac();
int FindTargetMac();
unsigned WINAPI TargetLoopPacket();

int main(int argc, char **argv) {
	unsigned int cnt = 0;
	unsigned int ret = 0;
	int res = 0;
	DWORD dwRetVal;
	struct bpf_program fcode;
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	PIP_ADAPTER_INFO pAdapter = NULL;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	int i = 0;
	int inum = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char packet_filter[] = "ip and tcp";
	bpf_u_int32 ipaddr, subnet;
	HANDLE hThread;
	unsigned threadID;
	struct pcap_pkthdr *pkt_hdr;
	u_char *pkt_data;
	
	if (argc != 2) {
		fprintf(stderr, "Usage : <%s Target IP>\n", argv[0]);
		return -1;
	}
	
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}
	/*여기서 부터 나중에 리눅스에서 할때는 어댑터 한개짜리로 구현*/
	
	my_addr = malloc(sizeof(struct in_addr));
	my_addr->S_un.S_addr = inet_addr("172.20.10.2");
	printf("my_addr : %ul\n", my_addr->S_un.S_addr);
	printf("my_addr ; %s\n",inet_ntoa(*my_addr));

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (1) {
			if ((ret = strcmp("172.20.10.2", pAdapter->IpAddressList.IpAddress.String)) == 0) {
				my_mac = malloc(sizeof(struct libnet_ether_addr));
				//strcpy(&my_mac->ether_addr_octet, &pAdapter->Address); 이거 안됨..왜??
				for (int g = 0; g < 6; g++) {
					my_mac->ether_addr_octet[g] = pAdapter->Address[g];
				}
				router_addr = malloc(sizeof(struct in_addr));
				router_addr->S_un.S_addr = inet_addr(pAdapter->GatewayList.IpAddress.String);
				break;
			}
			else {
				pAdapter = pAdapter->Next;
			}
		}
	}
	/*여기까지*/
	
	target_addr = malloc(sizeof(struct in_addr));
	target_addr->S_un.S_addr = inet_addr(argv[1]);

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr,"pcap_findalldevs_ex() Error : %s\n", errbuf);
		return -1;
	}

	for (i = 0, d = alldevs; d != NULL; i++, d = d->next) {
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
		printf("Out of Range...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (i = 0, d = alldevs; i < inum; i++, d = d->next);

	if ((adhandle = pcap_open(d->name, 65536, 0, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open() Error : %s\n", errbuf);
		return -1;
	}

	if (pcap_lookupnet(d->name, &ipaddr, &subnet, errbuf) < 0) {
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
	target_mac = malloc(sizeof(struct libnet_ether_addr));
	router_mac = malloc(sizeof(struct libnet_ether_addr));

	//FindGatewayMac();

	hThread = (HANDLE)_beginthreadex(NULL, 0, TargetLoopPacket, NULL, 0, &threadID);
	if (hThread == 0) {
		puts("_beginthreadex() error");
		return -1;
	}
	Sleep(3000);

	/*
	while (res=(pcap_next_ex(adhandle,&pkt_hdr,&pkt_data))>=0) {
		if (res == 0) {
			continue;
		}
		else {
			//여기에 패킷캡쳐 내용 작성
		}
	}
	*/
	
	return 0;

}

int FindGatewayMac() {
	struct libnet_arp_hdr *arp_hd = malloc(sizeof(struct libnet_arp_hdr));
	struct libnet_ethernet_hdr *ether_hd = malloc(sizeof(struct libnet_ethernet_hdr));
	bpf_u_int32 ipaddr, subnet;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res = 0;
	u_char ArpPacket[sizeof(struct libnet_arp_hdr) + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ether_addr) + sizeof(struct libnet_ether_addr) + sizeof(struct in_addr) + sizeof(struct in_addr)];

	for (int i = 0; i < 6; i++) {
		ether_hd->ether_dhost[i] = 0xff;
	}
	for (int g = 0; g < 6; g++) {
		ether_hd->ether_shost[g] = my_mac->ether_addr_octet[g];
	}
	ether_hd->ether_type = htons(ETHERTYPE_ARP);

	arp_hd->ar_hrd = htons(ARPHRD_ETHER);
	arp_hd->ar_pro = htons(0x0800);
	arp_hd->ar_hln = 0x06;
	arp_hd->ar_pln = 0x04;
	arp_hd->ar_op = htons(ARPOP_REQUEST);
	//arp_hd->ar_op = htons(ARPOP_REPLY);

	for (int j = 0; j < 6; j++) {
		router_mac->ether_addr_octet[j] = 0x00;
	}
	memcpy(ArpPacket, ether_hd, sizeof(struct libnet_ethernet_hdr));
	memcpy(ArpPacket + 14, arp_hd, sizeof(struct libnet_arp_hdr));
	memcpy(ArpPacket + 14 + 8, my_mac, sizeof(struct libnet_ether_addr));
	memcpy(ArpPacket + 14 + 8 + 6, &my_addr->S_un.S_addr, sizeof(struct in_addr));
	memcpy(ArpPacket + 14 + 8 + 6 + 4, router_mac, sizeof(struct libnet_ether_addr));
	memcpy(ArpPacket + 14 + 8 + 6 + 4 + 6, &router_addr->S_un.S_addr, sizeof(struct in_addr));

	if (pcap_sendpacket(adhandle, ArpPacket, sizeof(ArpPacket)) != 0)
	{
		fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(adhandle));
		free(arp_hd);
		free(ether_hd);
		//return -1;
	}
	else {
		printf("Success Gateway Send Packet\n");
		free(arp_hd);
		free(ether_hd);
	}

}

int FindTargetMac() {
	struct libnet_arp_hdr *arp_hd = malloc(sizeof(struct libnet_arp_hdr));
	struct libnet_ethernet_hdr *ether_hd = malloc(sizeof(struct libnet_ethernet_hdr));
	u_char ArpPacket[sizeof(struct libnet_arp_hdr) + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ether_addr) + sizeof(struct libnet_ether_addr) + sizeof(struct in_addr) + sizeof(struct in_addr)];

	for (int i = 0; i < 6; i++) {
		ether_hd->ether_dhost[i] = 0xff;
	}
	for (int g = 0; g < 6; g++) {
		ether_hd->ether_shost[g] = my_mac->ether_addr_octet[g];
	}
	ether_hd->ether_type = htons(ETHERTYPE_ARP);

	arp_hd->ar_hrd = htons(ARPHRD_ETHER);
	arp_hd->ar_pro = htons(0x0800);
	arp_hd->ar_hln = 0x06;
	arp_hd->ar_pln = 0x04;
	arp_hd->ar_op = htons(ARPOP_REQUEST);
	//arp_hd->ar_op = htons(ARPOP_REPLY);

	for (int j = 0; j < 6; j++) {
		target_mac->ether_addr_octet[j] = 0x00;
	}
	memcpy(ArpPacket, ether_hd, sizeof(struct libnet_ethernet_hdr));
	memcpy(ArpPacket + 14, arp_hd, sizeof(struct libnet_arp_hdr));
	memcpy(ArpPacket + 14 + 8, my_mac, sizeof(struct libnet_ether_addr));
	memcpy(ArpPacket + 14 + 8 + 6, &my_addr->S_un.S_addr, sizeof(struct in_addr));
	memcpy(ArpPacket + 14 + 8 + 6 + 4, target_mac, sizeof(struct libnet_ether_addr));
	memcpy(ArpPacket + 14 + 8 + 6 + 4 + 6, &target_addr->S_un.S_addr, sizeof(struct in_addr));

	if (pcap_sendpacket(adhandle, ArpPacket, sizeof(ArpPacket)) != 0)
	{
		fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(adhandle));
		free(arp_hd);
		free(ether_hd);
		//return -1;
	}
	else {
		printf("Success Target Send Packet\n");
		free(arp_hd);
		free(ether_hd);
	}

}


unsigned WINAPI TargetLoopPacket() {
	struct libnet_arp_hdr *arp_hd;
	struct libnet_ethernet_hdr *ether_hd;
	struct libnet_ether_addr *tmac_addr;
	struct in_addr *t_addr;
	struct pcap_pkthdr *pkt_hdr;
	u_char *pkt_data;
	int res = 0;
	int cnt = 0;

	while (router_mac == NULL) {
		FindTargetMac();
		/*여기에서 타겟 mac주소를 받아온다*/
		while (res = (pcap_next_ex(adhandle, &pkt_hdr, &pkt_data)) >= 0) {
			if (res == 0) {
				continue;
			}
			else {
				ether_hd = (struct libnet_ethernet_hdr *)pkt_data;
				arp_hd = (struct libnet_arp_hdr *)((char *)pkt_data + 14);
				//my_mac = (struct libnet_ether_addr *)((char *)(arp_hd)+8);
				//my_addr = (struct in_addr *)((char *)(my_mac)+6);
				tmac_addr = (struct libnet_ether_addr *)((char *)(arp_hd)+18);
				t_addr = (struct in_addr *)((char *)(arp_hd)+24);
				cnt++;
				if ((arp_hd->ar_op == htons(ARPOP_REPLY)) && (t_addr->S_un.S_addr == target_addr->S_un.S_addr)) {
					memcpy(target_mac, t_addr, sizeof(struct libnet_ether_addr));
					for (int g = 0; g < 6; g++) {
						printf("%02x-", target_mac->ether_addr_octet[g]);
					}
				}
				if (cnt == 10) {
					break;
				}
			}
		}
		sleep(3000);
	}
	return 0;
}
