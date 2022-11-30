#ifndef ARP_H_INCLUDED
#define ARP_H_INCLUDED

#include <iostream>
#include <pcap.h>

///.:DEFINICION:.///
//Encabezados de funciones
///Campos de encabezado
int bin_decimal(const u_char*, const int, const int);//De binario a decimal
void Tipo_Hardware(const u_char*, pcap_t*);
void Tipo_Protocolo(const u_char*, pcap_t*);
void Longitud_DirHardware(const u_char*, pcap_t*);
void Longitud_DirProtocolo(const u_char*, pcap_t*);
void CodigoOperacion(const u_char*, pcap_t*);
void DirMAC_Emisor(const u_char*, pcap_t*);
void DirIP_Emisor(const u_char*, pcap_t*);
void DirMAC_Receptor(const u_char*, pcap_t*);
void DirIP_Receptor(const u_char*, pcap_t*);

#endif // ARP_H_INCLUDED
