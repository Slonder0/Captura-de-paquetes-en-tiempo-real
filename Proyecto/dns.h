#ifndef DNS_H_INCLUDED
#define DNS_H_INCLUDED

#include <iostream>
#include <math.h>
#include "arp.h"

///.:DEFINICION:.///
//Encabezados de funciones
//Campos de cabecera
///HEADER
void ID_DNS(const u_char*, pcap_t*);
void Flags_DNS(const u_char*, pcap_t*);
unsigned int QDcount(const u_char*, pcap_t*);//Contador question
unsigned int ANcount(const u_char*, pcap_t*);//Contador answer
unsigned int NScount(const u_char*, pcap_t*);//Contador authority
unsigned int ARcount(const u_char*, pcap_t*);//Contador additional records
///QUESTION
void NombreQD_DNS(const u_char*, pcap_t*);
void NombreAN_DNS(const u_char*, pcap_t*,unsigned int);
void Tipo_DNS(const u_char*, pcap_t*);
void Class_DNS(const u_char*, pcap_t*);
///ANSWER
//Usar mismas funciones de question
void TTL_DNS(const u_char*, pcap_t*);
int Longitud_DNS(const u_char*, pcap_t*);
int RDATA(const u_char*, pcap_t*);

#endif // DNS_H_INCLUDED
