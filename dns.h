#ifndef DNS_H_INCLUDED
#define DNS_H_INCLUDED

#include <iostream>
#include <math.h>
#include "arp.h"

///.:DEFINICION:.///
//Encabezados de funciones
//Campos de cabecera
///HEADER
void ID_DNS(const u_char*, pcap_t*,int);
void Flags_DNS(const u_char*, pcap_t*,int);
unsigned int QDcount(const u_char*, pcap_t*,int);//Contador question
unsigned int ANcount(const u_char*, pcap_t*,int);//Contador answer
unsigned int NScount(const u_char*, pcap_t*,int);//Contador authority
unsigned int ARcount(const u_char*, pcap_t*,int);//Contador additional records
///QUESTION
void NombreQD_DNS(const u_char*, pcap_t*,int);
void NombreAN_DNS(const u_char*, pcap_t*,unsigned int,int);
void Tipo_DNS(const u_char*, pcap_t*,int);
void Class_DNS(const u_char*, pcap_t*,int);
///ANSWER
//Usar mismas funciones de question
void TTL_DNS(const u_char*, pcap_t*,int);
int Longitud_DNS(const u_char*, pcap_t*,int);
int RDATA(const u_char*, pcap_t*,int);

#endif // DNS_H_INCLUDED
