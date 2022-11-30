#include "arp.h"
#include <math.h>

using namespace std;
/*Funcion para convertir de binario a decimal
NOTA: "byte" es la cantidad de bits a transformar*/

int bin_decimal(const u_char* dato, const int byte, const int actual){
    //Variables para la conversion
    int numbin = 0;
    char binario[byte];

    for(int i=byte-1;i>=0;i--){
        //Conversion a binario del byte
        binario[i] =((dato[actual] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            numbin+=pow(2,i);
        }
    }

    return numbin;
}

void Tipo_Hardware(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    printf("Tipo de Hardware: ");
    //Leer bytes
    for(int cont=14; cont<16; cont++){
        datobin += bin_decimal(dato,8,cont);
    }

    //datobin = bin_decimal(dato,16);

    printf("%d ",datobin);

    switch(datobin){
        case 1:
            printf("Ethernet (10 Mb)\n");
            break;
        case 6:
            printf("IEEE 802 Networks\n");
            break;
        case 7:
            printf("ARCNET\n");
            break;
        case 15:
            printf("Frame Relay\n");
            break;
        case 16:
            printf("Asynchronous Transfer Mode (ATM)\n");
            break;
        case 17:
            printf("HDLC\n");
            break;
        case 18:
            printf("Fibre Channel\n");
            break;
        case 19:
            printf("Asynchronous Transfer Mode (ATM)\n");
            break;
        case 20:
            printf("Serial line\n");
            break;
    }
}

void Tipo_Protocolo(const u_char* dato, pcap_t* archivo){
    //dato = fgetc(archivo); //Primer par de bytes a leer
    printf("Tipo de protocolo: %02X:",dato[16]);//16

    //IP = 0800, ARP = 0806, RARP = 8035, IPv6 = 86DD
    switch(dato[16]){
        case 0x08:
            //dato = fgetc(archivo);//Introducir el siguiente par de bytes
            //Verificar si es IP o ARP
            if(dato[17] == 0x00){
               printf("%02X",dato[17]);
               printf("  IPv4\n");
            }
            if(dato[17] == 0x06){
                printf("%02X",dato[17]);
                printf("  ARP\n");
            }
            break;
        case 0x80:
            if(dato[17] == 0x35){
                printf("Tipo de campo: %02X",dato[17]);
                printf("  RARP\n");
            }
            break;
        case 0x86:
            if(dato[17] == 0xDD){
                printf("Tipo de campo: %02X",dato[17]);
                printf("  IPv6\n");
            }
            break;
        default:
            printf("No coincide\n");
            break;
    }
}

void Longitud_DirHardware(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    printf("Longitud de la direccion de hardware: ");
    //Leer bytes
    for(int cont = 18; cont < 19;cont++){//19
        //dato = fgetc(archivo);
        datobin = bin_decimal(dato,8,cont);
    }
    //datobin = bin_decimal(dato,16,cont);

    printf("%d ",datobin);
    printf("\n");
}

void Longitud_DirProtocolo(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    printf("Longitud de la direccion de protocolo: ");
    //Leer bytes
    for(int cont = 19; cont < 20;cont++){//21
        //dato = fgetc(archivo);
        datobin = bin_decimal(dato,8,cont);
    }
    //datobin = bin_decimal(dato,16);

    printf("%d ",datobin);
    printf("\n");
}

void CodigoOperacion(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    printf("Codigo: ");
    //Leer bytes
    for(int cont=20; cont<22; cont++){//23
        //dato = fgetc(archivo);
        datobin = bin_decimal(dato,8,cont);
    }

    //datobin = bin_decimal(dato,16);

    printf("%d ",datobin);

    switch(datobin){
        case 1:
            printf("Solicitud ARP (ARP request)\n");
            break;
        case 2:
            printf("Respuesta ARP (ARP reply)\n");
            break;
        case 3:
            printf("Solicitud RARP (RARP request)\n");
            break;
        case 4:
            printf("Respuesta RARP (RARP reply)\n");
            break;
    }
}

void DirMAC_Emisor(const u_char* dato, pcap_t* archivo){
    printf("Direccion Hardware del emisor: ");
    for(int cont=22; cont<28; cont++){//
        //dato = fgetc(archivo);
        printf("%02X",dato[cont]);
        if(cont != 27){
            printf(":");
        }
    }
    printf("\n");
}

void DirIP_Emisor(const u_char* dato, pcap_t* archivo){
    //Tamanio de 4 bytes
    int datobin;
    printf("Direccion IP del emisor: ");

    for(int cont=28; cont<32; cont++){//33
        //dato = fgetc(archivo);//Leer cada byte
        datobin = bin_decimal(dato,8,cont);//Conversion a decimal
        if(cont != 31){
            printf("%d.",datobin);
        }
        else{
            printf("%d",datobin);
        }
    }

    printf("\n");
}

void DirMAC_Receptor(const u_char* dato, pcap_t* archivo){
    printf("Direccion hadware del receptor: ");
    for(int cont=32; cont<38; cont++){//37
        //dato = fgetc(archivo);
        printf("%02X",dato[cont]);
        if(cont != 37){
            printf(":");
        }
    }
    printf("\n");
}

void DirIP_Receptor(const u_char* dato, pcap_t* archivo){
    //Tamanio de 4 bytes
    int datobin;
    printf("Direccion IP del receptor: ");

    for(int cont=38; cont<42; cont++){//Final 41
        //dato = fgetc(archivo);//Leer cada byte
        datobin = bin_decimal(dato,8,cont);//Conversion a decimal
        if(cont != 41){
            printf("%d.",datobin);
        }
        else{
            printf("%d",datobin);
        }
    }

    printf("\n");
}
