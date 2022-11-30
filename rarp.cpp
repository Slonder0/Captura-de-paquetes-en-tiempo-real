#include "rarp.h"
#include <math.h>

void Direccion_destino(unsigned char dato,FILE* archivo){
    printf("Direccion Destino: ");
    dato = fgetc(archivo);
    for(int i=0; i<8; i++){
           printf("%x", dato);
           printf("%x:", dato);
        }
        printf("\n");
}
//void Limite_salto(unsigned char dato, FILE* archivo){
   // printf("Tiempo de Vida (TTL): ");
   // dato = fgetc(archivo);
    //int datobin=0;
   // char binario[8];
    //for(int i=7;i>=0;i--){
       // binario[i] =((dato & (1 << i)) ? '1' : '0');
      //  if(binario[i] == '1'){
       //     datobin+=pow(2,i);
       // }
 //   }

    //printf("%d",datobin);

   // printf("\n");
//}






