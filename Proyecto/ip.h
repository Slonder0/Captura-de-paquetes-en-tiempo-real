#ifndef IP_H_INCLUDED
#define IP_H_INCLUDED

#include <iostream>
#include <pcap.h>
#include "arp.h"

///.:DEFINICION:.///
//Encabezados de funciones
///Cabeceras de datagrama IPv4
void Version(const u_char*, pcap_t*);
int IHL(const u_char*);
void Servicio(const u_char*, pcap_t*);
void Longitud(const u_char*, pcap_t*);
void Identificador(const u_char*, pcap_t*);
void Indicador(const u_char*, pcap_t*);
void Flags(const u_char*, pcap_t*);
void TTL(const u_char*, pcap_t*);
int Protocolo(const u_char*, pcap_t*);
void Checksum(const u_char*, pcap_t*);//Suma de Control de Cabecera
void IP_Origen(const u_char*, pcap_t*);
void IP_Destino(const u_char*, pcap_t*);
void Opciones_IP(const u_char*, pcap_t*);
void Campos(const u_char*, pcap_t*);//Contiene 5 campos diferentes
void Relleno(const u_char*, pcap_t*);

///Protocolo ICMP
void Tipo_MensaInfo(const u_char*, pcap_t*);
void CodigoError(const u_char*, pcap_t*);
void ChecksumICMP(const u_char*, pcap_t*);

///Cabeceras de datagrama IPv6
void Flowlabel(const u_char*, pcap_t*);//Version y Traffic class
void Payload_lenght(const u_char*, pcap_t*);
int NextHeader(const u_char*, pcap_t*);
void Limite_salto(const u_char*, pcap_t*);
void DirOrigenIPv6(const u_char*, pcap_t*);
void DirDestinoIPv6(const u_char*, pcap_t*);

///Protocolo ICMPv6
void Tipo_MensaInfoICMPv6(const u_char*, pcap_t*);
void ChecksumICMPv6(const u_char*, pcap_t*);

#endif // IP_H_INCLUDED
