#ifndef RARP_H_INCLUDED
#define RARP_H_INCLUDED

#include <iostream>

void Version_(unsigned char, FILE*);
void Clase_trafico(unsigned char, FILE*);
void Etiqueta_flujo(unsigned char, FILE*);
void Tamano_datos(unsigned char, FILE*);
void Encabezado_siguiente(unsigned char, FILE*);
void Limite_salto(unsigned char, FILE*);
void Direccion_origen(unsigned char, FILE*);
void Direccion_destino(unsigned char, FILE*);

#endif
