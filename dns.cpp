#include "dns.h"

using namespace std;

///CAMPOS DEL HEADER
void ID_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    printf("ID: ");
    //Leer bytes
    //IPv4
    if(dato[13]== 0x00){
        if(tipo == 6){//TCP
            for(int cont = 54; cont < 56; cont++){//55
                printf("%02X",dato[cont]);
            }
        }
        else{//UDP
            for(int cont = 42; cont < 44; cont++){//43
                printf("%02X",dato[cont]);
            }
        }

    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont = 74; cont < 76; cont++){//75
                printf("%02X",dato[cont]);
            }
        }
        else{//UDP
            for(int cont = 62; cont < 64; cont++){//63
                printf("%02X",dato[cont]);
            }
        }
    }
    printf("\n");
}

void Flags_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    int QR,opcode,AA,TC,RD,RA,AD,CD,RCODE;
    int datobin = 0,i;
    char binario[16];

    printf("Flags: ");
    //Leer primeros bytes

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
                //QR
    for(i=0; i<1; i++){
        binario[i] =((dato[56] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i);
        }
    }

    QR = datobin;
    printf(" QR: %d\n",QR);

    datobin = 0;
    //Opcode
    for(i=1; i<5; i++){
        binario[i] =((dato[56] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-1);
        }
    }

    opcode = datobin;
    printf("\tOpcode: %d ",opcode);
    switch(opcode){
        case 0:
            printf("consulta estandar (QUERY)\n");
            break;
        case 1:
            printf("consulta inversa (IQUERY)\n");
            break;
        case 2:
            printf("solicitud del estado del servidor (STATUS)\n");
            break;
        default:
            printf("\n");
            break;
    }

    datobin = 0;
    //AA
    for(i=5; i<6; i++){
        binario[i] =((dato[56] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-5);
        }
    }

    AA = datobin;
    printf("\tAA: %d\n",AA);

    datobin = 0;
    //TC
    for(i=6; i<7; i++){
        binario[i] =((dato[56] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-6);
        }
    }

    TC = datobin;
    printf("\tTC: %d\n",TC);

    datobin = 0;
    //RD
    for(i=7; i<8; i++){
        binario[i] =((dato[56] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-7);
        }
    }

    RD = datobin;
    printf("\tRD: %d\n",RD);

    //Leer otro par de bytes
    //dato = fgetc(archivo);

    datobin = 0;
    //RA
    for(i=8; i<9; i++){
        binario[i] =((dato[57] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-8);
        }
    }

    RA = datobin;
    printf("\tRA: %d\n",RA);

    datobin = 0;
    //Z
    for(i=9; i<12; i++){
        binario[i] =((dato[57] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-9);
        }
    }

    datobin = 0;
    //Rcode
    for(i=12; i<16; i++){
        binario[i] =((dato[57] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-12);
        }
    }

        RCODE = datobin;
        printf("\tRCODE: %d ",RCODE);

        switch(RCODE){
        case 0:
            printf("ningun error\n");
            break;
        case 1:
            printf("error de formato\n");
            break;
        case 2:
            printf("fallo en el servidor\n");
            break;
        case 3:
            printf("error en nombre\n");
            break;
        case 4:
            printf("no implementado\n");
            break;
        case 5:
            printf("rechazado\n");
            break;
            }
        }//Fin del if
        else{//UDP
                //QR
    for(i=0; i<1; i++){
        binario[i] =((dato[44] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i);
        }
    }

    QR = datobin;
    printf(" QR: %d\n",QR);

    datobin = 0;
    //Opcode
    for(i=1; i<5; i++){
        binario[i] =((dato[44] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-1);
        }
    }

    opcode = datobin;
    printf("\tOpcode: %d ",opcode);
    switch(opcode){
        case 0:
            printf("consulta estandar (QUERY)\n");
            break;
        case 1:
            printf("consulta inversa (IQUERY)\n");
            break;
        case 2:
            printf("solicitud del estado del servidor (STATUS)\n");
            break;
        default:
            printf("\n");
            break;
    }

    datobin = 0;
    //AA
    for(i=5; i<6; i++){
        binario[i] =((dato[44] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-5);
        }
    }

    AA = datobin;
    printf("\tAA: %d\n",AA);

    datobin = 0;
    //TC
    for(i=6; i<7; i++){
        binario[i] =((dato[44] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-6);
        }
    }

    TC = datobin;
    printf("\tTC: %d\n",TC);

    datobin = 0;
    //RD
    for(i=7; i<8; i++){
        binario[i] =((dato[44] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-7);
        }
    }

    RD = datobin;
    printf("\tRD: %d\n",RD);

    //Leer otro par de bytes
    //dato = fgetc(archivo);

    datobin = 0;
    //RA
    for(i=8; i<9; i++){
        binario[i] =((dato[45] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-8);
        }
    }

    RA = datobin;
    printf("\tRA: %d\n",RA);

    datobin = 0;
    //Z
    for(i=9; i<12; i++){
        binario[i] =((dato[45] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-9);
        }
    }

    datobin = 0;
    //Rcode
    for(i=12; i<16; i++){
        binario[i] =((dato[45] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-12);
        }
    }

    RCODE = datobin;
    printf("\tRCODE: %d ",RCODE);

    switch(RCODE){
        case 0:
            printf("ningun error\n");
            break;
        case 1:
            printf("error de formato\n");
            break;
        case 2:
            printf("fallo en el servidor\n");
            break;
        case 3:
            printf("error en nombre\n");
            break;
        case 4:
            printf("no implementado\n");
            break;
        case 5:
            printf("rechazado\n");
            break;
    }
        }//fin del else
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
        //QR
    for(i=0; i<1; i++){
        binario[i] =((dato[76] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i);
        }
    }

    QR = datobin;
    printf(" QR: %d\n",QR);

    datobin = 0;
    //Opcode
    for(i=1; i<5; i++){
        binario[i] =((dato[76] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-1);
        }
    }

    opcode = datobin;
    printf("\tOpcode: %d ",opcode);
    switch(opcode){
        case 0:
            printf("consulta estandar (QUERY)\n");
            break;
        case 1:
            printf("consulta inversa (IQUERY)\n");
            break;
        case 2:
            printf("solicitud del estado del servidor (STATUS)\n");
            break;
    }

    datobin = 0;
    //AA
    for(i=5; i<6; i++){
        binario[i] =((dato[76] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-5);
        }
    }

    AA = datobin;
    printf("\tAA: %d\n",AA);

    datobin = 0;
    //TC
    for(i=6; i<7; i++){
        binario[i] =((dato[76] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-6);
        }
    }

    TC = datobin;
    printf("\tTC: %d\n",TC);

    datobin = 0;
    //RD
    for(i=7; i<8; i++){
        binario[i] =((dato[76] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-7);
        }
    }

    RD = datobin;
    printf("\tRD: %d\n",RD);

    //Leer otro par de bytes
    //dato = fgetc(archivo);

    datobin = 0;
    //RA
    for(i=8; i<9; i++){
        binario[i] =((dato[77] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-8);
        }
    }

    RA = datobin;
    printf("\tRA: %d\n",RA);

    datobin = 0;
    //Z
    for(i=9; i<12; i++){
        binario[i] =((dato[77] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-9);
        }
    }

    datobin = 0;
    //Rcode
    for(i=12; i<16; i++){
        binario[i] =((dato[77] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-12);
        }
    }

        RCODE = datobin;
        printf("\tRCODE: %d ",RCODE);

        switch(RCODE){
        case 0:
            printf("ningun error\n");
            break;
        case 1:
            printf("error de formato\n");
            break;
        case 2:
            printf("fallo en el servidor\n");
            break;
        case 3:
            printf("error en nombre\n");
            break;
        case 4:
            printf("no implementado\n");
            break;
        case 5:
            printf("rechazado\n");
            break;
            }
        }//Fin del if
        else{
                    //QR
    for(i=0; i<1; i++){
        binario[i] =((dato[64] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i);
        }
    }

    QR = datobin;
    printf(" QR: %d\n",QR);

    datobin = 0;
    //Opcode
    for(i=1; i<5; i++){
        binario[i] =((dato[64] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-1);
        }
    }

    opcode = datobin;
    printf("\tOpcode: %d ",opcode);
    switch(opcode){
        case 0:
            printf("consulta estandar (QUERY)\n");
            break;
        case 1:
            printf("consulta inversa (IQUERY)\n");
            break;
        case 2:
            printf("solicitud del estado del servidor (STATUS)\n");
            break;
    }

    datobin = 0;
    //AA
    for(i=5; i<6; i++){
        binario[i] =((dato[64] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-5);
        }
    }

    AA = datobin;
    printf("\tAA: %d\n",AA);

    datobin = 0;
    //TC
    for(i=6; i<7; i++){
        binario[i] =((dato[64] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-6);
        }
    }

    TC = datobin;
    printf("\tTC: %d\n",TC);

    datobin = 0;
    //RD
    for(i=7; i<8; i++){
        binario[i] =((dato[64] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-7);
        }
    }

    RD = datobin;
    printf("\tRD: %d\n",RD);

    //Leer otro par de bytes
    //dato = fgetc(archivo);

    datobin = 0;
    //RA
    for(i=8; i<9; i++){
        binario[i] =((dato[65] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-8);
        }
    }

    RA = datobin;
    printf("\tRA: %d\n",RA);

    datobin = 0;
    //Z
    for(i=9; i<12; i++){
        binario[i] =((dato[65] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-9);
        }
    }

    datobin = 0;
    //Rcode
    for(i=12; i<16; i++){
        binario[i] =((dato[65] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin += pow(2,i-12);
        }
    }

    RCODE = datobin;
    printf("\tRCODE: %d ",RCODE);

    switch(RCODE){
        case 0:
            printf("ningun error\n");
            break;
        case 1:
            printf("error de formato\n");
            break;
        case 2:
            printf("fallo en el servidor\n");
            break;
        case 3:
            printf("error en nombre\n");
            break;
        case 4:
            printf("no implementado\n");
            break;
        case 5:
            printf("rechazado\n");
            break;
        }
        }//Fin del else
    }
}

unsigned int QDcount(const u_char* dato, pcap_t* archivo,int tipo){
    unsigned int datobin = 0;

    printf("QDCount: ");

    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=58; cont<60; cont++){//59
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=46; cont<48; cont++){//47
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=78; cont<80; cont++){//79
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{
            for(int cont=66; cont<68; cont++){//67
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }

    return datobin;
}

unsigned int ANcount(const u_char* dato, pcap_t* archivo,int tipo){
    unsigned int datobin = 0;

    printf("ANCount: ");

    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=60; cont<62; cont++){//61
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=48; cont<50; cont++){//59
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=80; cont<82; cont++){//81
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=68; cont<70; cont++){//69
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }

    return datobin;
}

unsigned int NScount(const u_char* dato, pcap_t* archivo,int tipo){
    unsigned int datobin = 0;

    printf("NSCount: ");

    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=62; cont<64; cont++){//63
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=50; cont<52; cont++){//51
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=82; cont<84; cont++){//83
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=70; cont<72; cont++){//71
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }

    return datobin;
}

unsigned int ARcount(const u_char* dato, pcap_t* archivo,int tipo){
    unsigned int datobin = 0;

    printf("ARCount: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=64; cont<66; cont++){//65
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=52; cont<54; cont++){//53
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }
    else{
        //IPv6
        if(tipo == 6){
            for(int cont=84; cont<86; cont++){//85
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{
            for(int cont=72; cont<74; cont++){//73
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }

    return datobin;
}

///CAMPOS DE QUESTION
void NombreQD_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    int datobin;//Dato para guardar decimal
    char dominio;

    printf("Nombre del dominio: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int i=66; i<130; i++){//129
                datobin = bin_decimal(dato,8,i);

                //Conversion a caracter
                dominio = datobin;
                if(dominio >= 46 and dominio <= 122){
                    printf("%c",dominio);
                }
                else{
                    printf("%d",datobin);
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
        else{//UDP
            for(int i=54; i<118; i++){//117
                datobin = bin_decimal(dato,8,i);

                //Conversion a caracter
                dominio = datobin;
                if(dominio >= 46 and dominio <= 122){
                    printf("%c",dominio);
                }
                else{
                    printf("%d",datobin);
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int i=86; i<150; i++){//149
                datobin = bin_decimal(dato,8,i);

                //Conversion a caracter
                dominio = datobin;
                if(dominio >= 46 and dominio <= 122){
                    printf("%c",dominio);
                }
                else{
                    printf("%d",datobin);
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
        else{//UDP
            for(int i=74; i<138; i++){//137
                datobin = bin_decimal(dato,8,i);

                //Conversion a caracter
                dominio = datobin;
                if(dominio >= 46 and dominio <= 122){
                    printf("%c",dominio);
                }
                else{
                    printf("%d",datobin);
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
    }
}

void Tipo_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    int datobin = 0;

    printf("Tipo: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=130; cont<132; cont++){//131
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            switch(datobin){
                case 1:
                    printf("A\n");
                    break;
                case 5:
                    printf("CNAME\n");
                    break;
                case 13:
                    printf("HINFO\n");
                    break;
                case 15:
                    printf("MX\n");
                    break;
                case 22:
                    printf("NS\n");
                    break;
                case 23:
                    printf("NS\n");
                    break;
                default:
                    printf("\n");
                    break;
            }
        }
        else{//UDP
            for(int cont=118; cont<120; cont++){//119
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            switch(datobin){
                case 1:
                    printf("A\n");
                    break;
                case 5:
                    printf("CNAME\n");
                    break;
                case 13:
                    printf("HINFO\n");
                    break;
                case 15:
                    printf("MX\n");
                    break;
                case 22:
                    printf("NS\n");
                    break;
                case 23:
                    printf("NS\n");
                    break;
                default:
                    printf("\n");
                    break;
            }
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=150; cont<152; cont++){//151
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            switch(datobin){
                case 1:
                    printf("A\n");
                    break;
                case 5:
                    printf("CNAME\n");
                    break;
                case 13:
                    printf("HINFO\n");
                    break;
                case 15:
                    printf("MX\n");
                    break;
                case 22:
                    printf("NS\n");
                    break;
                case 23:
                    printf("NS\n");
                    break;
                default:
                    printf("\n");
                    break;
            }
        }
        else{//UDP
            for(int cont=138; cont<140; cont++){//139
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            switch(datobin){
                case 1:
                    printf("A\n");
                    break;
                case 5:
                    printf("CNAME\n");
                    break;
                case 13:
                    printf("HINFO\n");
                    break;
                case 15:
                    printf("MX\n");
                    break;
                case 22:
                    printf("NS\n");
                    break;
                case 23:
                    printf("NS\n");
                    break;
                default:
                    printf("\n");
                    break;
            }
        }
    }
}

void Class_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    int datobin = 0;

    printf("Clase: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=132; cont<134; cont++){//133
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            if(datobin == 1){
                printf("IN\n");
            }

            if(datobin == 3){
                printf("CH\n");
            }
        }
        else{//UDP
            for(int cont=120; cont<122; cont++){//121
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            if(datobin == 1){
                printf("IN\n");
            }

            if(datobin == 3){
                printf("CH\n");
            }
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=152; cont<154; cont++){//153
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            if(datobin == 1){
                printf("IN\n");
            }

            if(datobin == 3){
                printf("CH\n");
            }
        }
        else{//UDP
            for(int cont=140; cont<142; cont++){//141
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d ",datobin);

            if(datobin == 1){
                printf("IN\n");
            }

            if(datobin == 3){
                printf("CH\n");
            }
        }
    }
}

///CAMPOS ANSWER
void NombreAN_DNS(const u_char* dato, pcap_t* archivo, unsigned int AN,int tipo){
    int datobin;//Dato para guardar decimal
    char dominio;

    printf("Nombre del dominio: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int i=134; i<198; i++){//197
                //Si se activa el campo de respuesta, mostrar puntero (PTR)
                if(AN > 0 and i < 136){
                    printf("%02X",dato[i]);
                }
                else{
                    datobin = bin_decimal(dato,8,i);

                    //Conversion a caracter
                    dominio = datobin;
                    if(dominio >= 46 and dominio <= 122){
                        printf("%c",dominio);
                    }
                    else{
                        printf("%d",datobin);
                    }
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
        else{//UDP
            for(int i=122; i<186; i++){//185
                //Si se activa el campo de respuesta, mostrar puntero (PTR)
                if(AN > 0 and i < 124){
                    printf("%02X",dato[i]);
                }
                else{
                    datobin = bin_decimal(dato,8,i);

                    //Conversion a caracter
                    dominio = datobin;
                    if(dominio >= 46 and dominio <= 122){
                        printf("%c",dominio);
                    }
                    else{
                        printf("%d",datobin);
                    }
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int i=154; i<218; i++){//217
                //Si se activa el campo de respuesta, mostrar puntero (PTR)
                if(AN > 0 and i < 156){
                    printf("%02X",dato[i]);
                }
                else{
                    datobin = bin_decimal(dato,8,i);

                    //Conversion a caracter
                    dominio = datobin;
                    if(dominio >= 46 and dominio <= 122){
                        printf("%c",dominio);
                    }
                    else{
                        printf("%d",datobin);
                    }
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
        else{//UDP
            for(int i=142; i<206; i++){//205
                //Si se activa el campo de respuesta, mostrar puntero (PTR)
                if(AN > 0 and i < 144){
                    printf("%02X",dato[i]);
                }
                else{
                    datobin = bin_decimal(dato,8,i);

                    //Conversion a caracter
                    dominio = datobin;
                    if(dominio >= 46 and dominio <= 122){
                        printf("%c",dominio);
                    }
                    else{
                        printf("%d",datobin);
                    }
                }

                if(datobin == 0){
                    break;
                }
            }

            printf("\n");
        }
    }
}

void TTL_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    int datobin = 0;

    printf("TTL: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=198; cont<202; cont++){//201
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d sec\n",datobin);
        }
        else{//UDP
            for(int cont=186; cont<190; cont++){//189
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d sec\n",datobin);
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=218; cont<222; cont++){//221
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d sec\n",datobin);
        }
        else{//UDP
            for(int cont=206; cont<210; cont++){//209
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d sec\n",datobin);
        }
    }
}

int Longitud_DNS(const u_char* dato, pcap_t* archivo,int tipo){
    int datobin = 0;

    printf("Longitud de datos: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=202; cont<204; cont++){//203
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=190; cont<192; cont++){//191
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }
    else{
        //IPv6
        if(tipo == 6){//TCP
            for(int cont=222; cont<224; cont++){//223
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
        else{//UDP
            for(int cont=210; cont<212; cont++){//211
                datobin += bin_decimal(dato,8,cont);
            }

            printf("%d\n",datobin);
        }
    }

    return datobin;
}

int RDATA(const u_char* dato, pcap_t* archivo,int tipo){
    int datobin = 0,longitud;
    char ascii;

    longitud = Longitud_DNS(dato,archivo,tipo);

    printf("RDATA: ");

    //IPv4
    if(dato[13] == 0x00){
        if(tipo == 6){//TCP
            for(int cont=204; cont<longitud; cont++){
                datobin += bin_decimal(dato,8,cont);

                //Imprimir IPv4
                if(longitud == 4){
                    printf("%d.",datobin);
                }
                else{
                    //Conversion a ASCII
                    ascii = datobin;

                    printf("%c",ascii);
                }
            }

            printf("\n");
        }
        else{//UDP
            for(int cont=192; cont<longitud; cont++){
                datobin += bin_decimal(dato,8,cont);

                //Imprimir IPv4
                if(longitud == 4){
                    printf("%d.",datobin);
                }
                else{
                    //Conversion a ASCII
                    ascii = datobin;

                    printf("%c",ascii);
                }
            }

            printf("\n");
        }
    }
    else{
        //IPv6
        //224
        if(tipo == 6){//TCP
            for(int cont=224; cont<longitud; cont++){
                datobin += bin_decimal(dato,8,cont);

                //Imprimir IPv4
                if(longitud == 4){
                    printf("%d.",datobin);
                }
                else{
                    //Conversion a ASCII
                    ascii = datobin;

                    printf("%c",ascii);
                }
            }

            printf("\n");
        }
        else{//UDP
            for(int cont=212; cont<longitud; cont++){
                datobin += bin_decimal(dato,8,cont);

                //Imprimir IPv4
                if(longitud == 4){
                    printf("%d.",datobin);
                }
                else{
                    //Conversion a ASCII
                    ascii = datobin;

                    printf("%c",ascii);
                }
            }

            printf("\n");
        }
    }

    return longitud;
}
