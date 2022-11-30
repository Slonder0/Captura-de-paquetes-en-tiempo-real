#include "ip.h"
#include <math.h>
#include <cstdlib>
#include <stdlib.h>
#include <string>

using namespace std;

///IP version 4

void Version(const u_char* dato, pcap_t* archivo){
    //IPv4 = 0100, IPv6 = 0110
    int datobin=0,i,tam=0;
    printf("Version: ");
    //dato = fgetc(archivo);
    char binario[8];
    for(i=7;i>=4;i--){//Leer el primere byte del par de bytes
        //Conversion a binario del byte
        binario[i] =((dato[14] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i-4);
        }
    }

    //Mostrar el tipo de IP
    printf("%d",datobin);

    printf("\n");

    ///IHL

    printf("Tamano de cabecera (IHL): ");
    tam = IHL(dato)/8;
    printf("%d ",tam);
    printf("bytes");

    printf("\n");
}

int IHL(const u_char* dato){
    int datobin=0,i,tam=0;
    char binario[8];
    for(i=3;i>=0;i--){//Leer el ultimo par de los bytes
        binario[i] =((dato[14] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    tam = datobin * 32;

    return tam;
}

void Servicio(const u_char* dato, pcap_t* archivo){
      /*000: De rutina.
      001: Prioritario.
      010: Inmediato.
      011: Relámpago.
      100: Invalidación relámpago.
      101: Procesando llamada crítica y de emergencia.
      110: Control de trabajo de Internet.
      111: Control de red*/
    printf("Tipo de Servicio: ");
    //dato = fgetc(archivo);
    int i,datobin=0;
    char binario[8];
    for(i=7;i>=5;i--){//Leer primeros 3 bits
        binario[i] =((dato[15] & (1 << i)) ? '1' : '0');//15
        if(binario[i] == '1'){
            datobin+=pow(2,i-5);
        }
    }
    //Verificacion de bits de prioridad
    switch(datobin){
        case 0:
            printf("De rutina\n");
            break;
        case 1:
            printf("Prioritario\n");
            break;
        case 2:
            printf("Intermedio\n");
            break;
        case 3:
            printf("Relampago\n");
            break;
        case 4:
            printf("Invalidacion relampago\n");
            break;
        case 5:
            printf("Procesando llamada critica y de emergencia\n");
            break;
        case 6:
            printf("Control de trabajo de Internet\n");
            break;
        case 7:
            printf("Control de red\n");
            break;
        default:
            printf("Error...\n");
            break;
    }

    //Desglose de bits, caracteristicas del servicio
    /*Bit 3: Retardo. 0 = normal ; 1 = bajo.
      Bit 4: Rendimiento. 0= normal; 1= alto.
      Bit 5: Fiabilidad. 0=normal; 1= alta.
      Bit 6-7: No usados. Reservados para uso futuro.*/

    datobin = 0;
    for(i=4;i>=0;i--){
        binario[i] =((dato[15] & (1 << i)) ? '1' : '0');
    }
    if(binario[4] == '0'){
        printf("\t\t  Retardo,     normal\n");
    }
    else{
        printf("\t\t  Retardo,     bajo\n");
    }

    if(binario[3] == '0'){
        printf("\t\t  Rendimiento,  normal\n");
    }
    else{
        printf("\t\t  Rendimiento,  bajo\n");
    }

    if(binario[2] == '0'){
        printf("\t\t  Fiabilidad,    normal\n");
    }
    else{
        printf("\t\t  Fiabilidad,    bajo\n");
    }
}

void Longitud(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    char binario[16];
    for(int cont=16; cont<18; cont++){
        for(int i=7;i>=0;i--){
            binario[i] =((dato[cont] & (1 << i)) ? '1' : '0');//17
            if(binario[i] == '1'){
                datobin+=pow(2,i);
            }
        }
    }
    //Conversion a decimal
    /*for(int i=15;i>=0;i--){
        binario[i] =((dato & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }*/

    printf("Longitud total: %d",datobin);
    printf("\n");
}

void Identificador(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    char id[16],iden[16];
    printf("Identificador: ");
    //Leer los datos
    for(int cont=18; cont<20; cont++){//19
        //dato = fgetc(archivo);
        datobin += bin_decimal(dato,8,cont);
    }

    //Transferir cadena de bits al nuevo arreglo
    for(int i=15; i>=0; i--){
        iden[i] = id[i];
    }

    //Convertir a decimal
    for(int i=15; i>=0; i--){
        if(iden[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    printf("%d",datobin);
    printf("\n");
}

void Flags(const u_char* dato, pcap_t* archivo){
    char binario[16];
    int datobin=0,i;
    /*bit 0: Reservado; debe ser 0
      bit 1: 0 = Divisible, 1 = No Divisible (DF)
      bit 2: 0 = Último Fragmento, 1 = Fragmento Intermedio (le siguen más fragmentos) (MF)*/

    printf("Flags: ");
    for(int i=1;i>=0;i--){
        dato[20];
    }
    for(i=2;i>=0;i--){
        binario[i] =((dato[20] & (1 << i)) ? '1' : '0');
    }
    if(binario[1] == '0'){
        printf("%c Divisible\n",binario[1]);
    }else if(binario[1] == '1'){
        printf("%c No Divisible (DF)\n",binario[1]);
    }else if(binario[0] == '0'){
        printf("%c Ultimo Fragmento\n",binario[0]);
    }else if(binario[0] == '1'){
        printf("%c Fragmento Intermedio (MF)\n",binario[0]);
    }

    ///Posicion de Fragmento

    printf("Posicion de Fragmento: ");
    for(i=12;i>=0;i--){
        binario[i] =((dato[21] & (1 << i)) ? '1' : '0');//22
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    printf("%d",datobin);
    printf("\n");
}

void TTL(const u_char* dato, pcap_t* archivo){
    printf("Tiempo de Vida (TTL): ");
    //dato = fgetc(archivo);
    int datobin=0;
    char binario[8];
    for(int i=7;i>=0;i--){
        binario[i] =((dato[22] & (1 << i)) ? '1' : '0');//23
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    printf("%d",datobin);

    printf("\n");
}

int Protocolo(const u_char* dato, pcap_t* archivo){
    /*1. ICMP v4
      6. TCP
      17. UDP
      58. ICMPv6
      118. STP
      121. SMP*/

    printf("Protocolo: ");
    //dato = fgetc(archivo);
    int datobin=0;
    char binario[8];
    for(int i=7;i>=0;i--){
        binario[i] =((dato[23] & (1 << i)) ? '1' : '0');//23
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    printf("%d ",datobin);

    switch(datobin){
        case 1:
            printf("ICMPv4\n");
            break;
        case 6:
            printf("TCP\n");
            break;
        case 17:
            printf("UDP\n");
            break;
        case 58:
            printf("ICMPv6\n");
            break;
        case 118:
            printf("STP\n");
            break;
        case 121:
            printf("SMP\n");
            break;
        default:
            printf("Otros...\n");
            break;
    }

    return datobin;
}

void Checksum(const u_char* dato, pcap_t* archivo){
    printf("Suma de Control de Cabecera: ");
    for(int cont=24; cont<26; cont++){
        //dato = fgetc(archivo);
        printf("%02X", dato[cont]);//25
        if(cont != 25){
            printf(":");
        }
    }

    printf("\n");
}

void IP_Origen(const u_char* dato, pcap_t* archivo){
    int datobin=0,cont=26;
    char ip[32];
    printf("Direccion IP de origen: ");
    //Leer los datos
    while(cont<30){
        //dato = fgetc(archivo);
        /*for(int i=0; i<8; i++){
            ip[i] =((dato[i] & (1 << i)) ? '1' : '0');//31
            if(ip[i] == '1'){
                datobin+=pow(2,i);
            }
        }*/
        if(cont  != 29){
            printf("%d.",dato[cont]);
        }
        else{
            printf("%d",dato[cont]);
        }
        datobin = 0;
        cont++;
    }

    printf("\n");
}

void IP_Destino(const u_char* dato, pcap_t* archivo){
    int datobin=0,cont=30;
    char ip[32];
    printf("Direccion IP de destino: ");
    //Leer los datos
    while(cont<34){
        if(cont  != 33){
            printf("%d.",dato[cont]);
        }
        else{
            printf("%d",dato[cont]);
        }
        datobin = 0;
        cont++;
    }

    printf("\n");
}

void Opciones_IP(const u_char* dato, pcap_t* archivo){
    printf("Opciones IP: \n");
    //Campo de 40 bytes
    for(int cont=0; cont<40; cont++){
        //dato = fgetc(archivo);
        printf("%02X", dato[cont]);//75
        if(cont != 39){
            printf(":");
        }
    }

    printf("\n");
}

void Campos(const u_char* dato, pcap_t* archivo){
    ///Flag copy (Fc)

    printf("Flag copy (Fc): ");
    //dato = fgetc(archivo);
    //Conversion a binario para tomar 1 bit
    int i,datobin=0;
    char binario[8];
    for(i=7;i>6;i--){
        binario[i] =((dato[i] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            printf("%c Copiado al fragmentarse\n",binario[i]);
        }
        else{
            printf("%c\n",binario[i]);
        }
    }

    ///Class Campo
    //Conversion a binario para tomar 2 bits
    /*0. Control
      1. Reservado
      2. Depuración y medición
      3. Reservado*/

    printf("Class: ");
    for(i=6;i>=5;i--){
        binario[i] =((dato[i] & (1 << i)) ? '1' : '0');
    }
    if(binario[6] == '0'){
        if(binario[5] == '0'){
            printf("Control\n");
        }
        else{
            printf("Reservado\n");
        }
    }
    else{
        if(binario[5] == '0'){
            printf("Depuracion y medicion\n");
        }
        else{
            printf("Reservado\n");
        }
    }

    ///Numero
    printf("Numero: ");
    for(i=5;i>=0;i--){
        binario[i] =((dato[i] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i-7);
        }
    }

    switch(datobin){
        case 0:
            printf("%d Final de lista de opciones\n",datobin);
            break;
        case 1:
            printf("%d No operation\n",datobin);
            break;
        case 2:
            printf("%d Security\n",datobin);
            break;
        case 3:
            printf("%d Loose source routine\n",datobin);
            break;
        case 4:
            printf("%d Internet time stamp\n",datobin);
            break;
        case 7:
            printf("%d Record route\n",datobin);
            break;
        case 9:
            printf("%d Strict source routing\n",datobin);
            break;
        default:
            printf("Error...\n");
            break;
    }

    ///Longitud
    //Lectura de byte
    //dato = fgetc(archivo);
    printf("Longitud: %02X",dato[77]);//77
    printf("\n");
}

void Relleno(const u_char* dato, pcap_t* archivo){
    printf("Relleno: ");
    //Leer los datos
    for(int i=0; i<4; i++){
        //dato = fgetc(archivo);
        printf("%02X",dato[i]);//81
        if(i != 3){
            printf(":");
        }
    }
}

///IMPLEMENTACION ICMP

void Tipo_MensaInfo(const u_char* dato, pcap_t* archivo){
    int numbin = 0;
    char code[8];
    printf("\tTipo de Mensaje: ");
    //Leer los datos
    //dato = fgetc(archivo);
    for(int i = 7; i>=0; i--){
        code[i] =((dato[34] & (1 << i)) ? '1' : '0');
        if(code[i]== '1'){
            numbin+=pow(2,1);
        }
    }

    printf("%d", numbin);
    printf("\n");
    printf("\tMensaje Informativo: ");

    //Mensajes Informativos
    // 0.- Echo Reply (respuesta de eco)
    // 3.- Destination Unreacheable (destino inaccesible)
    // 4.- Source Quench (disminución del tráfico desde el origen)
    // 5.- Redirect (redireccionar - cambio de ruta)
    // 8.- Echo (solicitud de eco)
    // 11.- Time Exceeded (tiempo excedido para un datagrama)
    // 12.- Parameter Problem (problema de parámetros
    // 13.- Timestamp (solicitud de marca de tiempo)
    // 14.- Timestamp Reply (respuesta de marca de tiempo)
    // 15.- Information Request (solicitud de información) - obsoleto-
    // 16.- Information Reply (respuesta de información) - obsoleto-
    // 17.- Addressmask (solicitud de máscara de dirección)
    // 18.- Addressmask Reply (respuesta de máscara de dirección

    switch(numbin){
    case 0:
        printf("Respuesta de eco ");
        break;
    case 3:
        printf("Destino inaccesible ");
        break;
    case 4:
        printf("Disminucion del trafico desde el origen ");
        break;
    case 5:
        printf("Redireccionar - cambio de ruta ");
        break;
    case 8:
        printf("Solicitud de eco");
        break;
    case 11:
        printf("Tiempo excedido para un datagrama");
        break;
    case 12:
        printf("Problema de parametros");
        break;
    case 13:
        printf("Solicitud de marca de tiempo");
        break;
    case 14:
        printf("Respuesta de marca de tiempo");
        break;
    case 15:
        printf("Solicitud de informacion - obsoleto-");
        break;
    case 16:
        printf("Respuesta de informacion - obsoleto-");
        break;
    case 17:
        printf("Solicitud de máscara de direccion");
        break;
    case 18:
        printf("Respuesta de máscara de direccion");
        break;
    default:
        printf("Error...");
        break;
    }

    printf("\n");
}

void CodigoError(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    char code[8];
    printf("\tCodigo de Error: ");
    //Leer los datos
    //dato = fgetc(archivo);
    for(int i=7; i>=0; i--){
        code[i] =((dato[35] & (1 << i)) ? '1' : '0');//35
        if(code[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    printf("%d ",datobin);
    /*
    0 no se puede llegar a la red
    1 no se puede llegar al host o aplicación de destino
    2 el destino no dispone del protocolo solicitado
    3 no se puede llegar al puerto destino o la aplicación destino no está libre
    4 se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario
    5 la ruta de origen no es correcta
    6 no se conoce la red destino
    7 no se conoce el host destino
    8 el host origen está aislado
    9 la comunicación con la red destino está prohibida por razones administrativas
    10 la comunicación con el host destino está prohibida por razones administrativas
    11 no se puede llegar a la red destino debido al Tipo de servicio
    12 no se puede llegar al host destino debido al Tipo de servicio
    */

    switch(datobin){
        case 0:
            printf("No se puede llegar a la red\n");
            break;
        case 1:
            printf("No se puede llegar al host o aplicacion de destino\n");
            break;
        case 2:
            printf("El destino no dispone del protocolo solicitado\n");
            break;
        case 3:
            printf("No se puede llegar al puerto destino o la aplicación destino no esta libre\n");
            break;
        case 4:
            printf("Se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario\n");
            break;
        case 5:
            printf("La ruta de origen no es correcta\n");
            break;
        case 6:
            printf("No se conoce la red destino\n");
            break;
        case 7:
            printf("No se conoce el host destino\n");
            break;
        case 8:
            printf("El host origen esta aislado\n");
            break;
        case 9:
            printf("La comunicacion con la red destino está prohibida por razones administrativas\n");
            break;
        case 10:
            printf("La comunicacion con el host destino está prohibida por razones administrativas\n");
            break;
        case 11:
            printf("No se puede llegar a la red destino debido al Tipo de servicio\n");
            break;
        case 12:
            printf("No se puede llegar al host destino debido al Tipo de servicio\n");
            break;
        default:
            printf("Error...\n");
            break;
    }
}

void ChecksumICMP(const u_char* dato, pcap_t* archivo){
    printf("\tSuma de Comprobacion (ICMP): ");
    for(int cont=36; cont<38; cont++){//37
        //dato = fgetc(archivo);
        printf("%02X", dato[cont]);
        if(cont != 1){
            printf(":");
        }
    }
    printf("\n");
}

///IP version 6

void Flowlabel(const u_char* dato, pcap_t* archivo){
    //IPv4 = 0100, IPv6 = 0110
    int datobin=0,i;
    printf("Version: ");
    //dato = fgetc(archivo);
    char binario[32];
    for(i=7;i>=4;i--){//Leer el primere byte del par de bytes
        //Conversion a binario del byte
        binario[i] =((dato[14] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i-4);
        }
    }
    //Mostrar el tipo de IP
    printf("%d",datobin);

    printf("\n");

    datobin = 0;
    ///Traffic class
    printf("Clase trafico: ");
    for(i=3;i>=0;i--){//4 bits restantes
        //Conversion a binario del byte
        binario[i] =((dato[14] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    //Verificacion de bits de prioridad
    switch(datobin){
        case 0:
            printf("  De rutina\n");
            break;
        case 1:
            printf("  Prioritario\n");
            break;
        case 2:
            printf("  Intermedio\n");
            break;
        case 3:
            printf("  Relampago\n");
            break;
        case 4:
            printf("  Invalidacion relampago\n");
            break;
        case 5:
            printf("  Procesando llamada critica y de emergencia\n");
            break;
        case 6:
            printf("  Control de trabajo de Internet\n");
            break;
        case 7:
            printf("  Control de red\n");
            break;
        default:
            printf("  Error...\n");
            break;
    }

    //Desglose de bits, caracteristicas del servicio
    /*Bit 3: Retardo. 0 = normal ; 1 = bajo.
      Bit 4: Rendimiento. 0= normal; 1= alto.
      Bit 5: Fiabilidad. 0=normal; 1= alta.
      Bit 6-7: No usados. Reservados para uso futuro.*/

    //dato = fgetc(archivo);
    for(i=3; i>=0; i--){//4 bits restantes
        //Conversion a binario del byte
        binario[i] =((dato[15] & (1 << i)) ? '1' : '0');
    }
    if(binario[3] == '0'){
        printf("\t\t Retardo,     normal\n");
    }
    else{
        printf("\t\t Retardo,     bajo\n");
    }

    if(binario[2] == '0'){
        printf("\t\t Rendimiento,  normal\n");
    }
    else{
        printf("\t\t Rendimiento,  bajo\n");
    }

    if(binario[1] == '0'){
        printf("\t\t Fiabilidad,    normal\n");
    }
    else{
        printf("\t\t Fiabilidad,    bajo\n");
    }

    printf("\n");

    datobin = 0;
    ///Flow label
    //Sobran 4 bits
    printf("Etiqueta de flujo: ");
    for(i=3; i>=0; i--){
        binario[i] =((dato[15] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
        //printf("%c",binario[i]);
    }

    for(int cont=16; cont<18; cont++){//17
        //dato = fgetc(archivo);
        datobin += bin_decimal(dato,8,cont);
    }

    printf("%d\n",datobin);
}

void Payload_lenght(const u_char* dato, pcap_t* archivo){
    int datobin=0;
    char binario[16];
    for(int cont=18; cont<20; cont++){//19
        datobin += bin_decimal(dato,8,cont);
    }
    //Conversion a decimal
    /*for(int i=15;i>=0;i--){
        binario[i] =((dato[20] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }*/

    printf("Tamano de los datos: %d",datobin);
    printf("\n");
}

int NextHeader(const u_char* dato, pcap_t* archivo){
	int numbin=0;
	//dato = fgetc(archivo);

	numbin = bin_decimal(dato,8,20);//Comienza en 20

	printf("Encabezado siguiente: %d ",numbin);

	switch(numbin){
        case 1:
            printf("ICMPv4\n");
            break;
        case 6:
            printf("TCP\n");
            break;
        case 17:
            printf("UDP\n");
            break;
        case 58:
            printf("ICMPv6\n");
            printf("\t\tICMPv6\n\n");
            printf("\t----------------------\n");
            break;
        case 118:
            printf("STP\n");
            break;
        case 121:
            printf("SMP\n");
            break;
        default:
            printf("Otros...\n");
            break;
    }

    return numbin;
}

void Limite_salto(const u_char* dato, pcap_t* archivo){
    printf("Hop limit: ");
    //dato = fgetc(archivo);
    int datobin=0;
    char binario[8];
    for(int i=7;i>=0;i--){
        binario[i] =((dato[21] & (1 << i)) ? '1' : '0');
        if(binario[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    printf("%d",datobin);

    printf("\n");
}

void DirOrigenIPv6(const u_char* dato, pcap_t* archivo){
    printf("Direccion de origen: ");
    //Campo de 16 bytes
    for(int cont=22; cont<38; cont++){//37
        //dato = fgetc(archivo);
        printf("%02X",dato[cont]);
        //Cada que sea par (lea 2 bytes) se ponen (:)
        if(cont%2 == 1 and cont != 37){
            printf(":");
        }
    }

    printf("\n");
}

void DirDestinoIPv6(const u_char* dato, pcap_t* archivo){
    printf("Direccion Destino: ");
    for(int i=38; i<54; i++){//53
        //dato = fgetc(archivo);
        printf("%02X",dato[i]);
        if(i%2 == 1 and i != 53){
            printf(":");
        }
    }

    printf("\n");
}

///IMPLEMENTACION ICMPv6
void Tipo_MensaInfoICMPv6(const u_char* dato, pcap_t* archivo){
    int numbin = 0;
    char tipoicmp[8];
    printf("\tTipo de Mensaje: ");

    //dato = fgetc(archivo);
    for(int i = 7; i>=0; i--){
        tipoicmp[i] =((dato[54] & (1 << i)) ? '1' : '0');
        if(tipoicmp[i]== '1'){
            numbin+=pow(2,i);
        }
    }

    printf("%d ", numbin);

    ///Campo Code
    int datobin=0;
    char code[8];
    //Conversion a decimal
    for(int i=7; i>=0; i--){
        code[i] =((dato[55] & (1 << i)) ? '1' : '0');
        if(code[i] == '1'){
            datobin+=pow(2,i);
        }
    }

    switch(numbin){
        case 1:
            {
            printf("Mensaje de destino inalcanzable\n");
            printf("\tCodigo de Error: ");
            printf("%d ",datobin);
            //Switch para campo codigo
            switch(datobin){
                case 0:
                    printf("No existe ruta destino\n");
                    break;
                case 1:
                    printf("Comunicacion con el destino administrativamente prohibida\n");
                    break;
                case 2:
                    printf("No asignado\n");
                    break;
                case 3:
                    printf("Direccion inalcanzable\n");
                    break;
            }
            break;
            }
        case 2:
            printf("Mensaje de paquete demasiado grande\n");
            printf("\tCodigo de Error: ");
            printf("%d",0);
            break;
        case 3:
            printf("Time Exceeded Message\n");
            printf("\tCodigo de Error: ");
            printf("%d ",datobin);
            if(datobin == 0){
                printf("El limite del salto excedido\n");
            }
            else{
                printf("Tiempo de reensamble de fragmento excedido\n");
            }
            break;
        case 4:
            {
            printf("Mensaje de problema de parametro\n");
            printf("\tCodigo de Error: ");
            printf("%d ",datobin);
            //Switch para campo codigo
            switch(datobin){
                case 0:
                    printf("El campo del encabezado erroneo encontro\n");
                    break;
                case 1:
                    printf("El tipo siguiente desconocido del encabezado encontro\n");
                    break;
                case 2:
                    printf("Opcion desconocida del IPv6 encontrada\n");
                    break;
            }
            break;
            }
        case 128:
            printf("Mensaje del pedido de eco\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        case 129:
            printf("Mensaje de respuesta de eco\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        case 133:
            printf("Mensaje de solicitud de router\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        case 134:
            printf("Mensaje de anuncio de router\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        case 135:
            printf("Mensaje de solicitud vecino\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        case 136:
            printf("Mensaje de anuncio de vecino\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        case 137:
            printf("Reoriente el mensaje\n");
            printf("\tCodigo de Error: ");
            printf("%d ",0);
            break;
        default:
            printf("Error...\n");
            break;
    }

    printf("\n");
}

void ChecksumICMPv6(const u_char* dato, pcap_t* archivo){
    printf("\tSuma de Comprobacion (ICMP): ");
    for(int cont=56; cont<58; cont++){
        //dato = fgetc(archivo);
        printf("%02X", dato[cont]);
        if(cont != 57){
            printf(":");
        }
    }
    printf("\n");
}
