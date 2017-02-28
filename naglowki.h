
#ifndef NAGLOWKI_H_
#define NAGLOWKI_H_

typedef struct {
	unsigned char dst_phy_address[6];
	unsigned char src_phy_address[6];
	unsigned char frame_type[2];
}eth;


typedef struct{
	unsigned char phy_address_space[2];
	unsigned char pro_address_space[2];
	unsigned char phy_address_length;
	unsigned char pro_address_length;
	unsigned char opcode[2];
	unsigned char source_phy_addr[6];
	unsigned char source_pro_addr[4];
	unsigned char destination_phy_addr[6];
	unsigned char destination_pro_addr[4];

}arp;

typedef struct {
	unsigned char IHL:4,
				  version:4;

} ip_ver_len;

typedef union {
	struct{
		unsigned short fragment_offset:13,
						          flags:3;
	} fields;
	unsigned short bits;

}ip_flag_off;

typedef struct {
	ip_ver_len ver_leng;
	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification;
	ip_flag_off flags;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned char src_ip[4];
	unsigned char dst_ip[4];
}ip;

typedef struct {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short identifier;
	unsigned short seq_number;

}icmp;

typedef struct {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned short length;
	unsigned short checksum;
}udp;


typedef union{
	struct {
		unsigned short control_bits:6,
				   	   reserved    :6,
					   data_offset :4;
		}fields;
	unsigned short bits;
}tcp;

typedef struct{
	struct{
		unsigned int   padding:8,
					   options:24;
	} fields;
	unsigned int bits;
}tcp_opcje_dopel;

typedef struct {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned int sequence_number;
	unsigned int ack;
	tcp flags;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
	tcp_opcje_dopel options_padding;
}ramka_tcp;

typedef struct {
	eth eth2;
	arp arp;
	unsigned char data[1476]; //1500-24
} pakiet_arp;

typedef struct {
	eth eth2;
	ip ip4;
	icmp icmp;
	unsigned char data[1464];//1500-14-18-4
}pakiet_icmp;

typedef struct{
	eth eth2;
	ip ip4;
	udp udp;
	unsigned char data[1460]; //1500-14-18-8

}pakiet_udp;

typedef struct{
	eth eth2;
	ip ip4;
	ramka_tcp tcp;
	unsigned char data[1448]; //1500-14-18-20
}pakiet_tcp;

#endif /* NAGLOWKI_H_ */
