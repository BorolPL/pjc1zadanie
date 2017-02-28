#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#include "naglowki.h"
#include "funkcje.h"

int main(void) {

	//definicja zmiennych
	int s; /*deskryptor gniazda*/
	int j;
	int i = 0;
	int length = 0;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaznik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (s == -1) {
		printf("Nie moge otworzyc gniazda\n");
	}

	while (i < 15) {
		//odbierz ramke Eth
		length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if (length == -1)
			printf("Problem z odbiorem ramki \n");
		else {
			i++;
			printf("Ramka: %d, dlugosc: %d [B]\n", i, length);
		}

#if 1
		//wypisz zawartosc bufora
		for (j = 0; j < length; j++) {
			printf("%02x ", *(etherhead + j));
		}
		printf("\n");
#endif
		eth et2;
		memcpy(&et2, etherhead, 14);

		short type = et2.frame_type[0] << 8 | et2.frame_type[1];

		switch (type) {
		case 0x0800:
			printf("IPv4 \n");
			ip ip4;
			memcpy(&ip4, etherhead + 14, 20);

			switch (ip4.protocol) {
			case 0x06:
				printf("Ip Protocol Type : TCP\n");
				pakiet_tcp TCP;
				unsigned int tcp_size = sizeof(pakiet_tcp);
				tcp_konwerter(&TCP, etherhead, tcp_size);
				//					drukuj_tcp(TCP);
				dodawanie_do_listy_tcp(TCP);
				break;
			case 0x01:
				printf("Ip Protocol Type : ICMP\n");
				pakiet_icmp ICMP;
				unsigned int icmp_size = sizeof(pakiet_icmp);
				icmp_konwerter(&ICMP, etherhead, icmp_size);
				//					drukuj_icmp(ICMP);
				dodawanie_do_listy_icmp(ICMP);
				break;
			case 0x11:
				printf("Ip Protocol Type : UDP\n");
				pakiet_udp UDP;
				unsigned int udp_size = sizeof(pakiet_udp);
				udp_konwerter(&UDP, etherhead, udp_size);
				//					drukuj_udp(UDP);
				dodawanie_do_listy_udp(UDP);
				break;
			default:
				printf(
						"Other Ethernet Ipv4 frame with protocol number : %02x\n",
						ip4.protocol);
			}
			break;
		case 0x0806:
			printf("ARP \n");
			pakiet_arp ARP;
			unsigned int arp_size = sizeof(pakiet_arp);
			arp_konwerter(&ARP, etherhead, arp_size);
			//			drukuj_arp(ARP);
			dodaj_do_listy_arp(ARP);
			break;
		default:
			break;
		}
	}
printf("==========================================przed wysłaniem==================================\n");
drukuj_liste_arp();
drukuj_liste_icmp();
drukuj_liste_udp();
drukuj_liste_tcp();
sleep(10);
printf("============================================wysylanie========================================\n");
wyslij_arp();
wyslij_icmp();
wyslij_udp();
wyslij_tcp();
printf("=================================================po wyslaniu==================================\n");
drukuj_liste_arp();
drukuj_liste_icmp();
drukuj_liste_udp();
drukuj_liste_tcp();

	return EXIT_SUCCESS;
}
