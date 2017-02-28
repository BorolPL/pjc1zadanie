#include "funkcje.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

void arp_konwerter(pakiet_arp *p_arp, unsigned char *bufor_eth_arp,
		unsigned int eth_arp) {
	memcpy(p_arp, bufor_eth_arp, eth_arp);
}

void icmp_konwerter(pakiet_icmp *p_icmp, unsigned char *bufor_eth_icmp,
		unsigned int size) {
	memcpy(p_icmp, bufor_eth_icmp, size);
	p_icmp->ip4.flags.bits = zamianaShortNaBigEndian(p_icmp->ip4.flags.bits);

	p_icmp->icmp.checksum = zamianaShortNaBigEndian(p_icmp->icmp.checksum);
	p_icmp->icmp.identifier = zamianaShortNaBigEndian(p_icmp->icmp.identifier);
	p_icmp->icmp.seq_number = zamianaShortNaBigEndian(p_icmp->icmp.seq_number);
	p_icmp->ip4.total_length = zamianaShortNaBigEndian(
			p_icmp->ip4.total_length);
	p_icmp->ip4.identification = zamianaShortNaBigEndian(
			p_icmp->ip4.identification);
	p_icmp->ip4.header_checksum = zamianaShortNaBigEndian(
			p_icmp->ip4.header_checksum);
	p_icmp->icmp.checksum = zamianaShortNaBigEndian(p_icmp->icmp.checksum);

}

void tcp_konwerter(pakiet_tcp *p_tcp, unsigned char *bufor_eth_tcp,
		unsigned int size) {
	memcpy(p_tcp, bufor_eth_tcp, size);
	p_tcp->ip4.flags.bits = zamianaShortNaBigEndian(p_tcp->ip4.flags.bits);
	memcpy(&p_tcp->tcp, bufor_eth_tcp + 34, sizeof(tcp));
	p_tcp->tcp.sequence_number = zamianaIntNaBigEndian(
			p_tcp->tcp.sequence_number);
	p_tcp->tcp.ack = zamianaIntNaBigEndian(p_tcp->tcp.ack);
	p_tcp->tcp.flags.bits = zamianaShortNaBigEndian(p_tcp->tcp.flags.bits);
	p_tcp->tcp.window = zamianaShortNaBigEndian(p_tcp->tcp.window);
	p_tcp->tcp.checksum = zamianaShortNaBigEndian(p_tcp->tcp.checksum);
	p_tcp->tcp.urgent_pointer = zamianaShortNaBigEndian(
			p_tcp->tcp.urgent_pointer);
	p_tcp->tcp.options_padding.bits = zamianaIntNaBigEndian(
			p_tcp->tcp.options_padding.bits);

	p_tcp->ip4.total_length = zamianaShortNaBigEndian(p_tcp->ip4.total_length);
	p_tcp->ip4.identification = zamianaShortNaBigEndian(
			p_tcp->ip4.identification);
	p_tcp->ip4.header_checksum = zamianaShortNaBigEndian(
			p_tcp->ip4.header_checksum);

	p_tcp->tcp.source_port = zamianaShortNaBigEndian(p_tcp->tcp.source_port);
	p_tcp->tcp.destination_port = zamianaShortNaBigEndian(
			p_tcp->tcp.destination_port);
}

void udp_konwerter(pakiet_udp *p_udp, unsigned char *buf_eth_udp,
		unsigned char size) {
	memcpy(p_udp, buf_eth_udp, size);
	p_udp->ip4.flags.bits = zamianaShortNaBigEndian(p_udp->ip4.flags.bits);
	p_udp->ip4.total_length = zamianaShortNaBigEndian(p_udp->ip4.total_length);
	p_udp->ip4.identification = zamianaShortNaBigEndian(
			p_udp->ip4.identification);
	p_udp->ip4.header_checksum = zamianaShortNaBigEndian(
			p_udp->ip4.header_checksum);

	p_udp->udp.source_port = zamianaShortNaBigEndian(p_udp->udp.source_port);
	p_udp->udp.destination_port = zamianaShortNaBigEndian(
			p_udp->udp.destination_port);
	p_udp->udp.length = zamianaShortNaBigEndian(p_udp->udp.length);
	p_udp->udp.checksum = zamianaShortNaBigEndian(p_udp->udp.checksum);
}

void drukuj_arp(pakiet_arp nagl_eth_arp) {

	printf("_______________________ARP _________________________________\n");
	printf("ETH\n\n");
	printf(" adres MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			nagl_eth_arp.eth2.dst_phy_address[0],
			nagl_eth_arp.eth2.dst_phy_address[1],
			nagl_eth_arp.eth2.dst_phy_address[2],
			nagl_eth_arp.eth2.dst_phy_address[3],
			nagl_eth_arp.eth2.dst_phy_address[4],
			nagl_eth_arp.eth2.dst_phy_address[5]);
	printf("adres MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n",
			nagl_eth_arp.eth2.src_phy_address[0],
			nagl_eth_arp.eth2.src_phy_address[1],
			nagl_eth_arp.eth2.src_phy_address[2],
			nagl_eth_arp.eth2.src_phy_address[3],
			nagl_eth_arp.eth2.src_phy_address[4],
			nagl_eth_arp.eth2.src_phy_address[5]);
	printf("rodzaj ramki    - 0x%02x%02x\n", nagl_eth_arp.eth2.frame_type[0],
			nagl_eth_arp.eth2.frame_type[1]);

	printf("\nARP\n\n");
	printf("protokol warstwy fizycznej- 0x%02x%02x\n",
			nagl_eth_arp.arp.phy_address_space[0],
			nagl_eth_arp.arp.phy_address_space[1]);
	printf("protokol warstwy sieciowej- 0x%02x%02x\n",
			nagl_eth_arp.arp.pro_address_space[0],
			nagl_eth_arp.arp.pro_address_space[1]);
	printf("Dl adresu fizycznego- %d\n", nagl_eth_arp.arp.phy_address_length);
	printf("Dł adresu sieciowego- %d\n", nagl_eth_arp.arp.pro_address_length);
	printf("Opcode- 0x%02x%02x\n", nagl_eth_arp.arp.opcode[0],
			nagl_eth_arp.arp.opcode[1]);
	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			nagl_eth_arp.arp.destination_phy_addr[0],
			nagl_eth_arp.arp.destination_phy_addr[1],
			nagl_eth_arp.arp.destination_phy_addr[2],
			nagl_eth_arp.arp.destination_phy_addr[3],
			nagl_eth_arp.arp.destination_phy_addr[4],
			nagl_eth_arp.arp.destination_phy_addr[5]);
	printf("adres IP Odbiorcy - %d.%d.%d.%d\n",
			nagl_eth_arp.arp.destination_pro_addr[0],
			nagl_eth_arp.arp.destination_pro_addr[1],
			nagl_eth_arp.arp.destination_pro_addr[2],
			nagl_eth_arp.arp.destination_pro_addr[3]);
	printf("adres MAC Nadawcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			nagl_eth_arp.arp.source_phy_addr[0],
			nagl_eth_arp.arp.source_phy_addr[1],
			nagl_eth_arp.arp.source_phy_addr[2],
			nagl_eth_arp.arp.source_phy_addr[3],
			nagl_eth_arp.arp.source_phy_addr[4],
			nagl_eth_arp.arp.source_phy_addr[5]);
	printf("adres IP Nadawcy - %d.%d.%d.%d\n",
			nagl_eth_arp.arp.source_pro_addr[0],
			nagl_eth_arp.arp.source_pro_addr[1],
			nagl_eth_arp.arp.source_pro_addr[2],
			nagl_eth_arp.arp.source_pro_addr[3]);

}
void drukuj_udp(pakiet_udp UDP) {
	printf("___________________________UDP___________________________\n");
	printf("ETH\n\n");

	printf("adres MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			UDP.eth2.dst_phy_address[0], UDP.eth2.dst_phy_address[1],
			UDP.eth2.dst_phy_address[2], UDP.eth2.dst_phy_address[3],
			UDP.eth2.dst_phy_address[4], UDP.eth2.dst_phy_address[5]);
	printf("adres MAC Nadawcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			UDP.eth2.src_phy_address[0], UDP.eth2.src_phy_address[1],
			UDP.eth2.src_phy_address[2], UDP.eth2.src_phy_address[3],
			UDP.eth2.src_phy_address[4], UDP.eth2.src_phy_address[5]);
	printf("rodzaj ramki   - 0x%02x%02x\n", UDP.eth2.frame_type[0],
			UDP.eth2.frame_type[1]);

	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n", UDP.ip4.ver_leng.version);
	printf("IHL IP - %d\n", UDP.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n", UDP.ip4.type_of_service);
	printf("Total Length - %d\n", UDP.ip4.total_length);
	printf("Identification - 0x%02x (%d)\n", UDP.ip4.identification,
			UDP.ip4.identification);
	printf("Flags - 0x%02x\n", UDP.ip4.flags.fields.flags);
	printf("Offset - %d\n", UDP.ip4.flags.fields.fragment_offset);
	printf("Czas życia - %d\n", UDP.ip4.time_to_live);
	printf("Protokół - %d\n", UDP.ip4.protocol);
	printf("Suma kontrolna nagłówka - 0x%02x\n", UDP.ip4.header_checksum);
	printf("adres IP Nadawcy - %d.%d.%d.%d\n", UDP.ip4.src_ip[0],
			UDP.ip4.src_ip[1], UDP.ip4.src_ip[2], UDP.ip4.src_ip[3]);
	printf("adres IP Odbiorcy - %d.%d.%d.%d\n", UDP.ip4.dst_ip[0],
			UDP.ip4.dst_ip[1], UDP.ip4.dst_ip[2], UDP.ip4.dst_ip[3]);

	printf("\n\nUDP\n\n");
	printf("numer portu Nadawcy   - %d\n", UDP.udp.source_port);
	printf("numer portu Odbiorcy  - %d\n", UDP.udp.destination_port);
	printf("dł.        - %d\n", UDP.udp.length);
	printf("crc - 0x%02x", UDP.udp.checksum);
}

void drukuj_icmp(pakiet_icmp nagl_eth_ip_icmp) {
	printf(
			"______________________________________ICMP____________________________________\n");
	printf("ETH\n\n");
	printf("adres MAC Odbiorcy- %02x:%02x:%02x:%02x:%02x:%02x\n",
			nagl_eth_ip_icmp.eth2.dst_phy_address[0],
			nagl_eth_ip_icmp.eth2.dst_phy_address[1],
			nagl_eth_ip_icmp.eth2.dst_phy_address[2],
			nagl_eth_ip_icmp.eth2.dst_phy_address[3],
			nagl_eth_ip_icmp.eth2.dst_phy_address[4],
			nagl_eth_ip_icmp.eth2.dst_phy_address[5]);
	printf("adres MAC Nadawcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			nagl_eth_ip_icmp.eth2.src_phy_address[0],
			nagl_eth_ip_icmp.eth2.src_phy_address[1],
			nagl_eth_ip_icmp.eth2.src_phy_address[2],
			nagl_eth_ip_icmp.eth2.src_phy_address[3],
			nagl_eth_ip_icmp.eth2.src_phy_address[4],
			nagl_eth_ip_icmp.eth2.src_phy_address[5]);
	printf("rodzaj ramki   - 0x%02x%02x\n", nagl_eth_ip_icmp.eth2.frame_type[0],
			nagl_eth_ip_icmp.eth2.frame_type[1]);
	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n", nagl_eth_ip_icmp.ip4.ver_leng.version);
	printf("IHL IP - %d\n", nagl_eth_ip_icmp.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n", nagl_eth_ip_icmp.ip4.type_of_service);
	printf("całkowita długość - %d\n", nagl_eth_ip_icmp.ip4.total_length);
	printf("Identification - 0x%02x (%d)\n",
			nagl_eth_ip_icmp.ip4.identification,
			nagl_eth_ip_icmp.ip4.identification);
	printf("Flags - 0x%02x\n", nagl_eth_ip_icmp.ip4.flags.fields.flags);
	printf("Offset - %d\n", nagl_eth_ip_icmp.ip4.flags.fields.fragment_offset);
	printf("TTL - %d\n", nagl_eth_ip_icmp.ip4.time_to_live);
	printf("Protokół - %d\n", nagl_eth_ip_icmp.ip4.protocol);
	printf("CRC nagłówka - 0x%02x\n", nagl_eth_ip_icmp.ip4.header_checksum);
	printf("adres IP Nadawcy - %d.%d.%d.%d\n", nagl_eth_ip_icmp.ip4.src_ip[0],
			nagl_eth_ip_icmp.ip4.src_ip[1], nagl_eth_ip_icmp.ip4.src_ip[2],
			nagl_eth_ip_icmp.ip4.src_ip[3]);
	printf("adres IP Odbiorcy - %d.%d.%d.%d\n", nagl_eth_ip_icmp.ip4.dst_ip[0],
			nagl_eth_ip_icmp.ip4.dst_ip[1], nagl_eth_ip_icmp.ip4.dst_ip[2],
			nagl_eth_ip_icmp.ip4.dst_ip[3]);

	printf("\n\nICMP\n\n");
	printf("Type - %d\n", nagl_eth_ip_icmp.icmp.type);
	printf("Code - %d\n", nagl_eth_ip_icmp.icmp.code);
	printf("CRC - %02x\n", nagl_eth_ip_icmp.icmp.checksum);
	printf("Identifier       - %d (0x%02x)\n", nagl_eth_ip_icmp.icmp.identifier,
			nagl_eth_ip_icmp.icmp.identifier);
	printf("Sequence Number  - %d (0x%02x)\n", nagl_eth_ip_icmp.icmp.seq_number,
			nagl_eth_ip_icmp.icmp.seq_number);

}
void drukuj_tcp(pakiet_tcp TCP) {
	printf(
			"\n\n__________________________________TCP________________________________\n");
	printf("ETH\n\n");

	printf("adres MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n",
			TCP.eth2.dst_phy_address[0], TCP.eth2.dst_phy_address[1],
			TCP.eth2.dst_phy_address[2], TCP.eth2.dst_phy_address[3],
			TCP.eth2.dst_phy_address[4], TCP.eth2.dst_phy_address[5]);
	printf("adres MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n",
			TCP.eth2.src_phy_address[0], TCP.eth2.src_phy_address[1],
			TCP.eth2.src_phy_address[2], TCP.eth2.src_phy_address[3],
			TCP.eth2.src_phy_address[4], TCP.eth2.src_phy_address[5]);
	printf("rodzaj ramki    - 0x%02x%02x\n", TCP.eth2.frame_type[0],
			TCP.eth2.frame_type[1]);

	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n", TCP.ip4.ver_leng.version);
	printf("IHL IP - %d\n", TCP.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n", TCP.ip4.type_of_service);
	printf("Całkowita długośc  - %d\n", TCP.ip4.total_length);
	printf("Identification - 0x%02x (%d)\n", TCP.ip4.identification,
			TCP.ip4.identification);
	printf("Flags - 0x%02x\n", TCP.ip4.flags.fields.flags);
	printf("Offset - %d\n", TCP.ip4.flags.fields.fragment_offset);
	printf("TTL - %d\n", TCP.ip4.time_to_live);
	printf("Protokół - %d\n", TCP.ip4.protocol);
	printf("CRC - 0x%02x\n", TCP.ip4.header_checksum);
	printf("IP Nadawcy - %d.%d.%d.%d\n", TCP.ip4.src_ip[0], TCP.ip4.src_ip[1],
			TCP.ip4.src_ip[2], TCP.ip4.src_ip[3]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n", TCP.ip4.dst_ip[0], TCP.ip4.dst_ip[1],
			TCP.ip4.dst_ip[2], TCP.ip4.dst_ip[3]);

	printf("\n\nTCP\n\n");
	printf("numer portu Nadawcy   - %d\n", TCP.tcp.source_port);
	printf("numer portu Odbiorcy  - %d\n", TCP.tcp.destination_port);
	printf("Sequence Number- 0x%02x\n", TCP.tcp.sequence_number);
	printf("ACK            - 0x%02x\n", TCP.tcp.ack);
	printf("Data Offset    - 0x%02x\n", TCP.tcp.flags.fields.data_offset);
	printf("Reserved       - 0x%02x\n", TCP.tcp.flags.fields.reserved);
	printf("Control Bits   - 0x%02x\n", TCP.tcp.flags.fields.control_bits);
	printf("Window         - 0x%04x\n", TCP.tcp.window);
	printf("CRC       - 0x%02x\n", TCP.tcp.checksum);
	printf("Urgent Pointer - 0x%04x\n", TCP.tcp.urgent_pointer);
	printf("Options        - 0x%04x\n", TCP.tcp.options_padding.fields.options);
	printf("Padding        - 0x%02x\n", TCP.tcp.options_padding.fields.padding);

}

unsigned short zamianaShortNaBigEndian(unsigned short data) {

	short num = ((data & 0xff00) >> 8) | ((data & 0x00ff) << 8);
	return num;

}

unsigned int zamianaIntNaBigEndian(unsigned int data) {
	int a0 = (data & 0x000000ff) << 24;
	int a1 = (data & 0x0000ff00) << 8;
	int a2 = (data & 0x00ff0000) >> 8;
	int a3 = (data & 0xff000000) >> 24;

	unsigned int num = a0 | a1 | a2 | a3;
	return num;
}

struct lista_arp *firstArp = NULL;
struct lista_arp *lastArp = NULL;

struct lista_tcp *firstTcp = NULL;
struct lista_tcp *lastTcp = NULL;

struct lista_udp *firstUdp = NULL;
struct lista_udp *lastUdp = NULL;

struct lista_icmp *firstIcmp = NULL;
struct lista_icmp *lastIcmp = NULL;

int dodaj_do_listy_arp(pakiet_arp packet) {
	struct lista_arp *new;

	new = (struct lista_arp *) malloc(sizeof(struct lista_arp));
	if (new == NULL) {
		return -1;
	}

	new->packet = packet;

	if (firstArp == NULL) {
		firstArp = new;
		lastArp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastArp;
		new->next = NULL;
		lastArp->next = new;
		lastArp = new;
	}
	return 0;
}

int removeArp(struct lista_arp *element) {
	if (element == NULL) {
		return -1;
	}
	if (firstArp != lastArp) {
		firstArp = firstArp->next;
		firstArp->back = NULL;
		free(element);
	} else {
		free(element);
		element = NULL;
		firstArp = NULL;
		lastArp= NULL;
	}
	return 0;
}

void drukuj_liste_arp() {
	printf("\n================== Pakiety ARP =============================\n");
	struct lista_arp *tmp = firstArp;
	while (tmp != NULL) {
		drukuj_arp(tmp->packet);
		tmp = tmp->next;

	}
}
void modyfyArpPacketToSend(pakiet_arp *packet) {
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->eth2.dst_phy_address, 6);
	memcpy(&packet->eth2.dst_phy_address, &packet->eth2.src_phy_address, 6);
	memcpy(&packet->eth2.src_phy_address, &tmpDstMac, 6);
}

void sendPacketARP(pakiet_arp *packet) {
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(pakiet_arp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->eth2.src_phy_address, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->eth2.dst_phy_address, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0806); //Protokol warstwy wyzszej: 0x0806 - pakiet arp

	memcpy(data, ether + 14, sizeof(pakiet_arp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		printf ("**************wysyłanie ramek ARP**************************\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_arp() {
	int x = 0;
	struct lista_arp *tmp = firstArp;
	while (tmp != NULL) {
		x++;
		modyfyArpPacketToSend(&tmp->packet);
		sendPacketARP(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			removeArp(tmp->back);
		} else {
			removeArp(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

int dodawanie_do_listy_icmp(pakiet_icmp packet) {

	struct lista_icmp *new;

	new = (struct lista_icmp *) malloc(sizeof(struct lista_icmp));
	if (new == NULL) {
		return -1;
	}
	new->packet = packet;

	if (firstIcmp == NULL) {
		firstIcmp = new;
		lastIcmp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastIcmp;
		new->next = NULL;
		lastIcmp->next = new;
		lastIcmp = new;
	}
	return 0;
}

int removeIcmp(struct lista_icmp *element) {
	if (element == NULL) {
		return -1;
	}
	if (firstIcmp != lastIcmp) {
		firstIcmp = firstIcmp->next;
		firstIcmp->back = NULL;
		free(element);
	} else {
		free(element);
		element = NULL;
		firstIcmp = NULL;
		lastIcmp = NULL;
	}
	return 0;
}

void drukuj_liste_icmp() {

	printf("\n================== Pakiety ICMP =============================\n");
	struct lista_icmp *tmp = firstIcmp;
	while (tmp != NULL) {
		drukuj_icmp(tmp->packet);
		tmp = tmp->next;
	}
}

void modyfyIcmpPacketToSend(pakiet_icmp *packet) {
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->eth2.dst_phy_address, 6);
	memcpy(&packet->eth2.dst_phy_address, &packet->eth2.src_phy_address, 6);
	memcpy(&packet->eth2.src_phy_address, &tmpDstMac, 6);
}

void sendPacketIcmp(pakiet_icmp *packet) {
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(pakiet_icmp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->eth2.src_phy_address, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->eth2.dst_phy_address, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0800); //Protokol warstwy wyzszej: 0x0806 - pakiet ip4

	memcpy(data, ether + 14, sizeof(pakiet_icmp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	printf ("**************wysyłanie ramek ICMP**************************\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_icmp() {
	int x = 0;
	struct lista_icmp *tmp = firstIcmp;
	while (tmp != NULL) {
		x++;
		modyfyIcmpPacketToSend(&tmp->packet);
		sendPacketIcmp(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			removeIcmp(tmp->back);
		} else {
			removeIcmp(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

int dodawanie_do_listy_udp(pakiet_udp packet) {
	struct lista_udp *new;

	new = (struct lista_udp *) malloc(sizeof(struct lista_udp));
	if (new == NULL) {
		return -1;
	}

	new->packet = packet;

	if (firstUdp == NULL) {
		firstUdp = new;
		lastUdp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastUdp;
		new->next = NULL;
		lastUdp->next = new;
		lastUdp = new;
	}
	return 0;
}
int removeUdp(struct lista_udp *element) {
	if (element == NULL) {
		return -1;
	}
	if (firstUdp != lastUdp) {
		firstUdp = firstUdp->next;
		firstUdp->back = NULL;
		free(element);
	} else {
		free(element);
		element = NULL;
		firstUdp = NULL;
		lastUdp = NULL;
	}
	return 0;
}

void drukuj_liste_udp() {
	printf("\n================== Pakiety UDP =============================\n");
	struct lista_udp *tmp = firstUdp;
	while (tmp != NULL) {
		drukuj_udp(tmp->packet);
		tmp = tmp->next;
	}
}

void modyfyUdpPacketToSend(pakiet_udp *packet) {
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->eth2.dst_phy_address, 6);
	memcpy(&packet->eth2.dst_phy_address, &packet->eth2.src_phy_address, 6);
	memcpy(&packet->eth2.src_phy_address, &tmpDstMac, 6);
}

void sendPacketUdp(pakiet_udp *packet) {
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(pakiet_udp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->eth2.src_phy_address, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->eth2.dst_phy_address, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet ipv4

	memcpy(data, ether + 14, sizeof(pakiet_udp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	printf ("**************wysyłanie ramek UDP**************************\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_udp() {
	int x = 0;
	struct lista_udp *tmp = firstUdp;
	while (tmp != NULL) {
		x++;
		modyfyUdpPacketToSend(&tmp->packet);
		sendPacketUdp(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			removeUdp(tmp->back);
		} else {
			removeUdp(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

int dodawanie_do_listy_tcp(pakiet_tcp packet) {
	struct lista_tcp *new;

	new = (struct lista_tcp *) malloc(sizeof(struct lista_tcp));
	if (new == NULL) {
		return -1;
	}

	new->packet = packet;

	if (firstTcp == NULL) {
		firstTcp = new;
		lastTcp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastTcp;
		new->next = NULL;
		lastTcp->next = new;
		lastTcp = new;
	}
	return 0;
}

int removeTcp(struct lista_tcp *element) {
	if (element == NULL) {
		return -1;
	}
	if (firstTcp != lastTcp) {
		firstTcp = firstTcp->next;
		firstTcp->back = NULL;
		free(element);
	} else {
		free(element);
		element = NULL;
		firstTcp = NULL;
		lastTcp = NULL;
	}

	return 0;
}

void drukuj_liste_tcp() {

	printf("\n================== Pakiety TCP =============================\n");
	struct lista_tcp *tmp = firstTcp;
	while (tmp != NULL) {
		drukuj_tcp(tmp->packet);
		tmp = tmp->next;
	}
}

void modyfyTcpPacketToSend(pakiet_tcp *packet) {
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->eth2.dst_phy_address, 6);
	memcpy(&packet->eth2.dst_phy_address, &packet->eth2.src_phy_address, 6);
	memcpy(&packet->eth2.src_phy_address, &tmpDstMac, 6);
}

void sendPacketTcp(pakiet_tcp *packet) {
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(pakiet_tcp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->eth2.src_phy_address, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->eth2.dst_phy_address, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0800); //Protokol warstwy wyzszej: 0x0806 - pakiet arp

	memcpy(data, ether + 14, sizeof(pakiet_arp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	printf ("**************wysyłanie ramek TCP**************************\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_tcp() {
	int x = 0;
	struct lista_tcp *tmp = firstTcp;
	while (tmp != NULL) {
		x++;
		modyfyTcpPacketToSend(&tmp->packet);
		sendPacketTcp(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			removeTcp(tmp->back);
		} else {
			removeTcp(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

