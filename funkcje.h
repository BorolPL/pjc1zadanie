
#ifndef FUNKCJE_H_
#define FUNKCJE_H_

#include "naglowki.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INTERFACE "eth0"

void arp_konwerter(pakiet_arp *p_arp,unsigned char *bufor_eth_arp,unsigned int eth_arp);
void icmp_konwerter(pakiet_icmp *p_icmp,unsigned char *bufor_eth_icmp,unsigned int size);
void tcp_konwerter(pakiet_tcp *p_tcp,unsigned char *bufor_eth_tcp,unsigned int size);
void udp_konwerter(pakiet_udp *p_udp,unsigned char *buf_eth_udp,unsigned char size);

void drukuj_arp(pakiet_arp nagl_eth_arp);
void drukuj_icmp(pakiet_icmp nagl_eth_ip_icmp);
void drukuj_udp(pakiet_udp UDP);
void drukuj_tcp(pakiet_tcp TCP);

unsigned int zamianaIntNaBigEndian(unsigned int data);
unsigned short zamianaShortNaBigEndian(unsigned short data);

//----------------------------listy---------------------------------------
struct lista_arp{
	pakiet_arp packet;
	struct lista_arp *next;
	struct lista_arp *back;
};


struct lista_tcp {
	pakiet_tcp packet;
	struct lista_tcp *next;
	struct lista_tcp *back;
};


struct lista_udp {
	pakiet_udp packet;
	struct lista_udp *next;
	struct lista_udp *back;
};


struct lista_icmp {
	pakiet_icmp packet;
	struct lista_icmp *next;
	struct lista_icmp *back;
};


int dodaj_do_listy_arp(pakiet_arp packet);
int dodawanie_do_listy_icmp(pakiet_icmp packet);
int dodawanie_do_listy_udp(pakiet_udp packet);
int dodawanie_do_listy_tcp(pakiet_tcp packet);

void drukuj_liste_arp();
void drukuj_liste_icmp();
void drukuj_liste_tcp();
void drukuj_liste_udp();

void wyslij_arp();
void wyslij_icmp();
void wyslij_udp();
void wyslij_tcp();

#endif /* FUNKCJE_H_ */
