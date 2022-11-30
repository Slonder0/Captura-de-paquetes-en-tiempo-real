/*Seminario de solucion de problemas de Redes de computadoras
Equipo #2, 4/11/2021
Protocolo DNS*/

#include <iostream>
#include <stdlib.h>
#include "ip.h"
#include "arp.h"
#include "tcpudp.h"
#include "dns.h"
#include <pcap.h>
#include <windows.h>

using namespace std;

void DireccionDestino(const u_char*, pcap_t*);
void DireccionOrigen(const u_char*, pcap_t*);
int Tipo(const u_char*, pcap_t*);
int cuenta = 0;

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#define LINE_LEN 16

int main(int argc, char **argv)
{
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
	printf("   Usage: pktdump_ex [-s source]\n\n"
		"   Examples:\n"
		"      pktdump_ex -s file.acp\n"
		"      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

	if(argc < 3)
	{
		printf("\nNo adapter selected: printing the device list:\n");
		/* The user didn't provide a packet source: Retrieve the local device list */
		if(pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s\n    ", ++i, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i==0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d):",i);
		scanf("%d", &inum);

		if (inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");

			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

		/* Open the adapter */
		if ((fp = pcap_open_live(d->name,	// name of the device
			65536,							// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}
	}
	else
	{
		/* Do not check for the switch type ('-s') */
		if ((fp = pcap_open_live(argv[2],	// name of the device
			65536,							// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}
	}

	int leido=0;
	/* Read the packets */
	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{
	    ++cuenta;
		if(res == 0)
			/* Timeout elapsed */
			continue;

        printf("\n\n");
		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

		/* Print the packet */
		for (i=1; (i < header->caplen + 1 ) ; i++)
		{
			printf("%.2X ", pkt_data[i-1]);
			if ( (i % LINE_LEN) == 0) printf("\n");
		}

		printf("\n\n");
		Sleep(1000*3);

		printf("---------- Ethernet ----------");
		printf("\n\n");

		DireccionDestino(pkt_data,fp);
        DireccionOrigen(pkt_data,fp);
        leido = Tipo(pkt_data,fp);

        //Datos
        printf("Datos: ");
        for(;(leido < header->caplen + 1); leido++){
            printf("%.2X:", pkt_data[leido-1]);
			if ( (leido % LINE_LEN) == 0) printf("\n");
        }

		if(cuenta == 10){
            break;
		}
	}

	if(res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	return 0;
}

//Visualizar la direccion MAC de destino
//Parametros palabra y el archivo
void DireccionDestino(const u_char* dato, pcap_t* archivo){
    printf("Direccion MAC de destino: ");
    for(int cont=0; cont<6; cont++){
        //dato = fgetc(archivo);
        printf("%02X",dato[cont]);
        if(cont != 5){
            printf(":");
        }
    }
    printf("\n");
}

//Visualizar la direccion MAC de origen
//Parametros palabra y el archivo
void DireccionOrigen(const u_char* dato, pcap_t* archivo){
    printf("Direccion MAC de origen: ");
    for(int cont=6; cont<12; cont++){
        //dato = fgetc(archivo);
        printf("%02X",dato[cont]);
        if(cont != 11){
            printf(":");
        }
    }
    printf("\n");
}

//Visualizar el tipo
int Tipo(const u_char* dato, pcap_t* archivo){
    unsigned int QD,AN,NS,AR;
    int tipo,destino,origen;
    //dato = fgetc(archivo); //Primer par de bytes a leer
    printf("Tipo de campo: %02X:",dato[12]);

    //IP = 0800, ARP = 0806, RARP = 8035, IPv6 = 86DD
    switch(dato[12]){
        case 0x08:
            //dato = fgetc(archivo);//Introducir el siguiente par de bytes
            //Verificar si es IP o ARP
            if(dato[13] == 0x00){
               printf("%02X",dato[13]);
               printf("  IP\n\n");
               printf("    IP\n");
               printf("------------\n");
               Version(dato,archivo);
               Servicio(dato,archivo);
               Longitud(dato,archivo);
               Identificador(dato,archivo);
               Flags(dato,archivo);
               TTL(dato,archivo);
               tipo = Protocolo(dato,archivo);
               //ICMPv4
               if(tipo == 1){
                    Tipo_MensaInfo(dato,archivo);
                    CodigoError(dato,archivo);
                    ChecksumICMP(dato,archivo);
               }
               Checksum(dato,archivo);
               IP_Origen(dato,archivo);
               IP_Destino(dato,archivo);
               //Opciones_IP(dato,archivo);
               //Campos(dato,archivo);
               //Relleno(dato,archivo);

               ///TCP
               if(tipo == 6){
                    printf("\n\t  TCP\n");
                    printf("-----------------------\n");
                    //dato = fgetc(archivo);
                    origen = PuertoOrigen(dato,archivo);
                    destino = Puerto_Destino(dato,archivo);
                    Numero_secuencia(dato,archivo);
                    AcuseRecibo(dato,archivo);
                    HeadLength(dato,archivo);
                    TamanoVentana(dato,archivo);
                    ChecksumTCP(dato,archivo);
                    PunteroUrgente(dato,archivo);

                    tipo = 54;
               }

               ///UDP
               if(tipo == 17){
                    printf("\n\t  UDP\n");
                    printf("-----------------------\n");
                    origen = PuertoOrigen(dato,archivo);
                    destino = Puerto_Destino(dato,archivo);
                    TotalLength(dato,archivo);
                    ChecksumUDP(dato,archivo);

                    tipo = 42;
               }

                if(origen == 53 or destino == 53){
                    ///DNS
                    printf("\n\t  DNS\n");
                    printf("-----------------------\n");
                    ID_DNS(dato,archivo);
                    Flags_DNS(dato,archivo);
                    QD = QDcount(dato,archivo);
                    AN = ANcount(dato,archivo);
                    NS = NScount(dato,archivo);
                    AR = ARcount(dato,archivo);
                    ///Question
                    for(int i=0; i<QD; i++){
                        NombreQD_DNS(dato,archivo);
                        Tipo_DNS(dato,archivo);
                        Class_DNS(dato,archivo);
                    }
                    ///Answer
                    for(int i=0; i<AN; i++){
                        NombreAN_DNS(dato,archivo,AN);
                        Tipo_DNS(dato,archivo);
                        Class_DNS(dato,archivo);
                        TTL_DNS(dato,archivo);
                        tipo = RDATA(dato,archivo);
                    }
                }

                return tipo;
            }
            if(dato[13] == 0x06){
                printf("%02X",dato[13]);
                printf("  ARP\n\n");
                printf("\t\tARP\n");
                printf("\t---------------------\n");
                Tipo_Hardware(dato,archivo);
                Tipo_Protocolo(dato,archivo);
                Longitud_DirHardware(dato,archivo);
                Longitud_DirProtocolo(dato,archivo);
                CodigoOperacion(dato,archivo);
                DirMAC_Emisor(dato,archivo);
                DirIP_Emisor(dato,archivo);
                DirMAC_Receptor(dato,archivo);
                DirIP_Receptor(dato,archivo);

                return 42;
            }
            break;
        case 0x80:
            //dato = fgetc(archivo);
            if(dato[13] == 0x35){
                printf("%02X",dato[13]);
                printf("  RARP\n\n");
                printf("\tRARP\n");
                printf("\t------------------------\n");
                Tipo_Hardware(dato,archivo);
                Tipo_Protocolo(dato,archivo);
                Longitud_DirHardware(dato,archivo);
                Longitud_DirProtocolo(dato,archivo);
                CodigoOperacion(dato,archivo);
                DirMAC_Emisor(dato,archivo);
                DirIP_Emisor(dato,archivo);
                DirMAC_Receptor(dato,archivo);
                DirIP_Receptor(dato,archivo);

                return 42;
            }
            break;
        case 0x86:
            //dato = fgetc(archivo);
            if(dato[13] == 0xDD){
                printf("%02X",dato[13]);
                printf("  IPv6\n\n");
                printf("\t\tIPv6\n");
                printf("\t------------------------\n");
                Flowlabel(dato,archivo);
                Payload_lenght(dato,archivo);
                tipo = NextHeader(dato,archivo);
                if(tipo == 58){
                    Tipo_MensaInfoICMPv6(dato,archivo);
                    ChecksumICMPv6(dato,archivo);
                }
                Limite_salto(dato,archivo);
                DirOrigenIPv6(dato,archivo);
                DirDestinoIPv6(dato,archivo);

                ///TCP
               if(tipo == 6){
                    printf("\n\t  TCP\n");
                    printf("-----------------------\n");
                    //dato = fgetc(archivo);
                    origen = PuertoOrigen(dato,archivo);
                    destino = Puerto_Destino(dato,archivo);
                    Numero_secuencia(dato,archivo);
                    AcuseRecibo(dato,archivo);
                    HeadLength(dato,archivo);
                    TamanoVentana(dato,archivo);
                    ChecksumTCP(dato,archivo);
                    PunteroUrgente(dato,archivo);

                    tipo = 74;
               }

               ///UDP
               if(tipo == 17){
                    printf("\n\t  UDP\n");
                    printf("-----------------------\n");
                    origen = PuertoOrigen(dato,archivo);
                    destino = Puerto_Destino(dato,archivo);
                    TotalLength(dato,archivo);
                    ChecksumUDP(dato,archivo);

                    tipo = 62;
                }

                if(origen == 53 or destino == 53){
                    ///DNS
                    printf("\n\t  DNS\n");
                    printf("-----------------------\n");
                    ID_DNS(dato,archivo);
                    Flags_DNS(dato,archivo);
                    QD = QDcount(dato,archivo);
                    AN = ANcount(dato,archivo);
                    NS = NScount(dato,archivo);
                    AR = ARcount(dato,archivo);
                    ///Question
                    for(int i=0; i<QD; i++){
                        NombreQD_DNS(dato,archivo);
                        Tipo_DNS(dato,archivo);
                        Class_DNS(dato,archivo);
                    }
                    ///Answer
                    for(int i=0; i<AN; i++){
                        NombreAN_DNS(dato,archivo,AN);
                        Tipo_DNS(dato,archivo);
                        Class_DNS(dato,archivo);
                        TTL_DNS(dato,archivo);
                        tipo = RDATA(dato,archivo);
                    }
                }

                return tipo;
            }
            break;
        default:
            printf("No coincide\n");
            break;
    }
}
