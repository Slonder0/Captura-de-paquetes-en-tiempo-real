#ifndef TCPUDP_H_INCLUDED
#define TCPUDP_H_INCLUDED

#include <iostream>
#include <math.h>
#include <pcap.h>
#include "arp.h"

///.:DEFINICION:.///
//Encabezados de funciones
//Campos de cabecera
int PuertoOrigen(const u_char*, pcap_t*);
int Puerto_Destino(const u_char*, pcap_t*);
void Numero_secuencia(const u_char*, pcap_t*);
void AcuseRecibo(const u_char*, pcap_t*);
void HeadLength(const u_char*, pcap_t*);//Longitud de cabecera, reservado y flags
void TamanoVentana(const u_char*, pcap_t*);
void ChecksumTCP(const u_char*, pcap_t*);//Suma de verificacion
void PunteroUrgente(const u_char*, pcap_t*);


///UDP
//Encabezados de funciones
void TotalLength(const u_char*, pcap_t*);
void ChecksumUDP(const u_char*, pcap_t*);

#endif // TCPUDP_H_INCLUDED
