#include "tcpudp.h"

using namespace std;

int PuertoOrigen(const u_char* dato, pcap_t* archivo){
    int datobin = 0;

    //IPv4
    if(dato[13] == 0x00){
        //Leer bytes
    for(int cont=34; cont<36; cont++){//35
        //dato = fgetc(archivo);
        datobin += bin_decimal(dato,8,cont);
    }

    if(datobin < 1024 and datobin > 0){
        printf("Puertos bien conocidos\n");
        printf("Puerto Origen: ");
        printf("%d ",datobin);
        switch(datobin){
            case 20:
                printf("Servicio FTP\n");
                break;
            case 21:
                printf("Servicio FTP \n");
                break;
            case 22:
                printf("Servicio SSH \n");
                break;
            case 23:
                printf("Servicio TELNET \n");
                break;
            case 25:
                printf("Servicio SMTP \n");
                break;
            case 53:
                printf("Servicio DNS \n");
                break;
            case 67:
                printf("Servicio DHCP \n");
                break;
            case 68:
                printf("Servicio DHCP \n");
                break;
            case 69:
                printf("Servicio TFTP \n");
                break;
            case 80:
                printf("Servicio HTTP \n");
                break;
            case 110:
                printf("Servicio POP 3 \n");
                break;
            case 143:
                printf("Servicio IMAP \n");
                break;
            case 443:
                printf("Servicio HTTPS \n");
                break;
            case 993:
                printf("Servicio IMAP SSL \n");
                break;
            case 995:
                printf("Servicio POP SSL \n");
                break;
            default:
                printf("\n");
                break;
        }
    }
    else if(datobin > 1023 and datobin < 49152){
        printf("Puertos registrados\n");
        printf("Puerto Origen: ");
        printf("%d \n",datobin);
    }
    else{
        printf("Puertos dinamicos o privados\n");
        printf("Puerto Origen: ");
        printf("%d \n",datobin);
    }
    }
    else{
        //IPv6
    for(int cont=54; cont<56; cont++){//55
        //dato = fgetc(archivo);
        datobin += bin_decimal(dato,8,cont);
    }

    if(datobin < 1024 and datobin > 0){
        printf("Puertos bien conocidos\n");
        printf("Puerto Origen: ");
        printf("%d ",datobin);
        switch(datobin){
            case 20:
                printf("Servicio FTP\n");
                break;
            case 21:
                printf("Servicio FTP \n");
                break;
            case 22:
                printf("Servicio SSH \n");
                break;
            case 23:
                printf("Servicio TELNET \n");
                break;
            case 25:
                printf("Servicio SMTP \n");
                break;
            case 53:
                printf("Servicio DNS \n");
                break;
            case 67:
                printf("Servicio DHCP \n");
                break;
            case 68:
                printf("Servicio DHCP \n");
                break;
            case 69:
                printf("Servicio TFTP \n");
                break;
            case 80:
                printf("Servicio HTTP \n");
                break;
            case 110:
                printf("Servicio POP 3 \n");
                break;
            case 143:
                printf("Servicio IMAP \n");
                break;
            case 443:
                printf("Servicio HTTPS \n");
                break;
            case 993:
                printf("Servicio IMAP SSL \n");
                break;
            case 995:
                printf("Servicio POP SSL \n");
                break;
            default:
                printf("\n");
                break;
        }
    }
    else if(datobin > 1023 and datobin < 49152){
        printf("Puertos registrados\n");
        printf("Puerto Origen: ");
        printf("%d \n",datobin);
    }
    else{
        printf("Puertos dinamicos o privados\n");
        printf("Puerto Origen: ");
        printf("%d \n",datobin);
    }
    }

    return datobin;
}

int Puerto_Destino(const u_char* dato, pcap_t* archivo){
    int datobin = 0;
    //Empieza en 36
    //IPv4
    if(dato[13] == 0x00){
        //Leer bytes
    for(int cont=36; cont<38; cont++){//37
        //dato = fgetc(archivo);
        datobin += bin_decimal(dato,8,cont);
    }

    if(datobin < 1024 and datobin > 0){
        printf("Puertos bien conocidos\n");
        printf("Puerto Destino: ");
        printf("%d ",datobin);
        switch(datobin){
            case 20:
                printf("Servicio FTP\n");
                break;
            case 21:
                printf("Servicio FTP \n");
                break;
            case 22:
                printf("Servicio SSH \n");
                break;
            case 23:
                printf("Servicio TELNET \n");
                break;
            case 25:
                printf("Servicio SMTP \n");
                break;
            case 53:
                printf("Servicio DNS \n");
                break;
            case 67:
                printf("Servicio DHCP \n");
                break;
            case 68:
                printf("Servicio DHCP \n");
                break;
            case 69:
                printf("Servicio TFTP \n");
                break;
            case 80:
                printf("Servicio HTTP \n");
                break;
            case 110:
                printf("Servicio POP 3 \n");
                break;
            case 143:
                printf("Servicio IMAP \n");
                break;
            case 443:
                printf("Servicio HTTPS \n");
                break;
            case 993:
                printf("Servicio IMAP SSL \n");
                break;
            case 995:
                printf("Servicio POP SSL \n");
                break;
            default:
                printf("\n");
                break;
        }
    }
    else if(datobin > 1023 and datobin < 49152){
        printf("Puertos registrados\n");
        printf("Puerto Destino: ");
        printf("%d \n",datobin);
    }
    else{
        printf("Puertos dinamicos o privados\n");
        printf("Puerto Destino: ");
        printf("%d \n",datobin);
    }
    }
    else{
        //IPv6
    for(int cont=56; cont<58; cont++){//57
        datobin += bin_decimal(dato,8,cont);
    }

    if(datobin < 1024 and datobin > 0){
        printf("Puertos bien conocidos\n");
        printf("Puerto Destino: ");
        printf("%d ",datobin);
        switch(datobin){
            case 20:
                printf("Servicio FTP\n");
                break;
            case 21:
                printf("Servicio FTP \n");
                break;
            case 22:
                printf("Servicio SSH \n");
                break;
            case 23:
                printf("Servicio TELNET \n");
                break;
            case 25:
                printf("Servicio SMTP \n");
                break;
            case 53:
                printf("Servicio DNS \n");
                break;
            case 67:
                printf("Servicio DHCP \n");
                break;
            case 68:
                printf("Servicio DHCP \n");
                break;
            case 69:
                printf("Servicio TFTP \n");
                break;
            case 80:
                printf("Servicio HTTP \n");
                break;
            case 110:
                printf("Servicio POP 3 \n");
                break;
            case 143:
                printf("Servicio IMAP \n");
                break;
            case 443:
                printf("Servicio HTTPS \n");
                break;
            case 993:
                printf("Servicio IMAP SSL \n");
                break;
            case 995:
                printf("Servicio POP SSL \n");
                break;
            default:
                printf("\n");
                break;
        }
    }
    else if(datobin > 1023 and datobin < 49152){
        printf("Puertos registrados\n");
        printf("Puerto Destino: ");
        printf("%d \n",datobin);
    }
    else{
        printf("Puertos dinamicos o privados\n");
        printf("Puerto Destino: ");
        printf("%d \n",datobin);
    }
    }

    return datobin;
}

void Numero_secuencia(const u_char* dato, pcap_t* archivo){
    int datobin=0;

    //IPv4
    if(dato[13] == 0x00){
        printf("Numero de secuencia: ");
        for(int cont=38; cont<42; cont++){//41
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n",datobin);
    }
    else{
        //IPv6
        printf("Numero de secuencia: ");
        for(int cont=58; cont<62; cont++){//61
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n",datobin);
    }
}

void AcuseRecibo(const u_char* dato, pcap_t* archivo){
    int datobin=0;

    //IPv4
    if(dato[13] == 0x00){
        printf("Numero de acuse de recibido: ");
        for(int cont=42; cont<46; cont++){//45
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n",datobin);
    }
    else{
        //IPv6
        printf("Numero de acuse de recibido: ");
        for(int cont=62; cont<66; cont++){//65
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n",datobin);
    }
}

void HeadLength(const u_char* dato, pcap_t* archivo){
    int datobin = 0,i,x;
    char longitud[16];

    //IPv4
    if(dato[13] == 0x00){
        /*for(i=15; i>=12; i--){
            longitud[i] =((dato[46] & (1 << i)) ? '1' : '0');//46
        }*/

        datobin = bin_decimal(dato,4,46);

        printf("Longitud de cabecera: %d",datobin);
        printf("\n");

    ///Reservado valores en 0
    ///Flags
    //Activar banderas cuando esten en 1
    x = 46;
    for(i=11; i>=0; i--){
        longitud[i] =((dato[x] & (1 << i)) ? '1' : '0');//46
        if(longitud[8] == '1'){
            printf("NS: ECN-nonce concealment protection\n");
        }
        if(i == 8){
            dato[++x];
        }
    }

    if(longitud[7] == '1'){
        printf("CWR: Congestion Window Reduced\n");
    }
    if(longitud[6] == '1'){
        printf("ECE: Congestion\n");
    }
    if(longitud[5] == '1'){
        printf("URG: Puntero urgente valido\n");
    }
    if(longitud[4] == '1'){
        printf("ACK: Acknowledgement\n");
    }
    if(longitud[3] == '1'){
        printf("PSH: Push\n");
    }
    if(longitud[2] == '1'){
        printf("RST: Reset\n");
    }
    if(longitud[1] == '1'){
        printf("SYN: Synchronize\n");
    }
    if(longitud[0] == '1'){
        printf("FIN: Finish\n");
    }

    }
    else{
        //IPv6
        for(i=15; i>=12; i--){
        longitud[i] =((dato[66] & (1 << i)) ? '1' : '0');//46
    }

    datobin = bin_decimal(dato,4,66);

    printf("Longitud de cabecera: %d",datobin);
    printf("\n");

    ///Reservado valores en 0
    ///Flags
    //Activar banderas cuando esten en 1
    x = 66;
    for(i=11; i>=0; i--){
        longitud[i] =((dato[x] & (1 << i)) ? '1' : '0');//46
        if(longitud[8] == '1'){
            printf("NS: ECN-nonce concealment protection\n");
        }
        if(i == 8){
            dato[++x];//67
        }
    }

    if(longitud[7] == '1'){
        printf("CWR: Congestion Window Reduced\n");
    }
    if(longitud[6] == '1'){
        printf("ECE: Congestion\n");
    }
    if(longitud[5] == '1'){
        printf("URG: Puntero urgente valido\n");
    }
    if(longitud[4] == '1'){
        printf("ACK: Acknowledgement\n");
    }
    if(longitud[3] == '1'){
        printf("PSH: Push\n");
    }
    if(longitud[2] == '1'){
        printf("RST: Reset\n");
    }
    if(longitud[1] == '1'){
        printf("SYN: Synchronize\n");
    }
    if(longitud[0] == '1'){
        printf("FIN: Finish\n");
    }

    }

}

void TamanoVentana(const u_char* dato, pcap_t* archivo){
    int datobin = 0;

    //IPv4
    if(dato[13] == 0x00){
        printf("Tamano de ventana: ");
        //Leer bytes
        for(int cont=48; cont<50; cont++){//49
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n",datobin);
    }
    else{
        //IPv6
        printf("Tamano de ventana: ");
        //Leer bytes
        for(int cont=68; cont<70; cont++){//69
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n",datobin);
    }
}

void ChecksumTCP(const u_char* dato, pcap_t* archivo){
    if(dato[13] == 0x00){
        printf("Suma de Control de TCP: ");
        for(int cont=50; cont<52; cont++){//51
            printf("%02X", dato[cont]);
            if(cont != 51){
                printf(":");
            }
        }

        printf("\n");
    }
    else{
        //IPv6
        printf("Suma de Control de TCP: ");
        for(int cont=70; cont<72; cont++){//71
            printf("%02X", dato[cont]);
            if(cont != 71){
                printf(":");
            }
        }

        printf("\n");
    }
}

void PunteroUrgente(const u_char* dato, pcap_t* archivo){
    int datobin = 0;

    //IPv4
    if(dato[13] == 0x00){
        printf("Puntero urgente: ");
        //Leer bytes
        for(int cont=52; cont<54; cont++){//53
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n", datobin);
    }
    else{
        //IPv6
        printf("Puntero urgente: ");
        //Leer bytes
        for(int cont=72; cont<74; cont++){//72
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n", datobin);
    }
}


///UDP

void TotalLength(const u_char* dato, pcap_t* archivo){
    int datobin = 0;

    if(dato[13] == 0x00){
        printf("Longitud total: ");
        for(int cont=38; cont<40; cont++){//39
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n", datobin);
    }
    else{
        //IPv6
        printf("Longitud total: ");
        for(int cont=58; cont<60; cont++){//39
            datobin += bin_decimal(dato,8,cont);
        }

        printf("%d\n", datobin);
    }
}

void ChecksumUDP(const u_char* dato, pcap_t* archivo){
    if(dato[13] == 0x00){
        printf("Suma de Control de UDP: ");
        for(int cont=40; cont<42; cont++){//41
            printf("%02X", dato[cont]);
            if(cont != 41){
                printf(":");
            }
        }

        printf("\n");
    }
    else{
        printf("Suma de Control de UDP: ");
        for(int cont=60; cont<62; cont++){//61
            printf("%02X", dato[cont]);
            if(cont != 61){
                printf(":");
            }
        }

        printf("\n");
    }
}
