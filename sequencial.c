/**
 * Universidad del Valle de Guatemala
 * Programación Paralela y Distribuida
 * Sección 10
 * 
 * Proyecto 2
 * 
 * Integrantes:
 * Abner Iván García Alegría 21285
 * Oscar Esteban Donis Martínez 21610
 * Dariel Eduardo Villatoro 20776
 * 
 * Archivo:     sequencial.c
 * 
 * Propósito:   Implementa un algoritmo de fuerza bruta para poder decifrar una 
 *              frase cifrada con el algoritmo DES de manera secuencial.
 *
 * Compile:     gcc -o sequencial sequencial.c -lcrypto -lssl -w
 * Run:         ./sequencial -k <llave>
 */

// Importamos librerías necesarias
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/des.h>
#include <time.h>

/**
 * Función para desencriptar un texto cifrado con DES
 * 
 * @param key Clave de encriptación
 * @param ciph Texto cifrado
 * @param len Longitud del texto cifrado
 */
void decrypt(long key, char *ciph, int len) {
    DES_cblock key_block; // Bloque de clave
    DES_key_schedule schedule; // Estructura de claves

    memset(key_block, 0, sizeof(DES_cblock)); // Inicializamos el bloque de clave
    memcpy(key_block, &key, sizeof(long)); // Copiamos la clave en el bloque

    DES_set_key_unchecked(&key_block, &schedule); // Guardamos la clave en la estructura de claves

    // Se va desencriptando el texto cifrado en bloques de 8 bits
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }
}

/**
 * Función para encriptar un texto con DES
 * 
 * @param key Clave de encriptación
 * @param ciph Texto a encriptar
 * @param len Longitud del texto a encriptar
 */
void encrypt(long key, char *ciph, int len) {
    DES_cblock key_block; // Bloque de clave
    DES_key_schedule schedule; // Estructura de claves

    memset(key_block, 0, sizeof(DES_cblock)); // Inicializamos el bloque de clave
    memcpy(key_block, &key, sizeof(long)); // Copiamos la clave en el bloque

    DES_set_key_unchecked(&key_block, &schedule); // Guardamos la clave en la estructura de claves

    // Se va encriptando el texto en bloques de 8 bits
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }
}

/**
 * Función para cargar un texto desde un archivo
 * 
 * @param filename Nombre del archivo
 * @param text Puntero a la variable texto donde cargar el contenido
 * @param length Longitud del texto cargado
 * @return 1 si se cargó correctamente, 0 si hubo un error
 */
int loadTextFromFile(const char *filename, char **text, int *length) {
    FILE *file = fopen(filename, "r"); // Se abre el archivo en modo lectura
    // Se verifica si hubo un error al abrir el archivo
    if (file == NULL) {
        perror("Error opening file");
        return 0;
    }

    fseek(file, 0, SEEK_END); // Movemos el puntero al final del archivo
    *length = ftell(file); // Obtenemos la longitud del archivo
    fseek(file, 0, SEEK_SET); // Movemos el puntero al inicio del archivo

    // Se reserva memoria para guardar el texto
    *text = (char *)malloc(*length);
    // Se verifica si hubo un error al reservar memoria
    if (*text == NULL) {
        perror("Memory allocation error");
        fclose(file);
        return 0;
    }

    // Se lee el contenido del archivo
    fread(*text, 1, *length, file);
    // Se cierra el archivo
    fclose(file);
    
    // Se retorna 1 para indicar que se cargó correctamente
    return 1;
}

char search[] = "es una prueba de";

/**
 * Función para intentar una clave en un texto cifrado
 * 
 * @param key Clave a intentar
 * @param ciph Texto cifrado
 * @param len Longitud del texto cifrado
 * 
 * @return 1 si la clave fue encontrada, 0 si no
 */
int tryKey(long key, char *ciph, int len){
  char temp[len+1]; // Se crea un arreglo temporal para guardar el texto encriptado y un cara
  memcpy(temp, ciph, len);  // Se copia el texto encriptado en el arreglo temporal
  temp[len]=0; // Se agrega un caracter nulo al final del arreglo
  decrypt(key, temp, len); // Se desencripta el texto con la clave a intentar
  
  // Se verifica si la clave fue encontrada en el texto desencriptado
  if (strstr((char *)temp, search) != NULL) {
    // Si es el caso se imprime la clave encontrada
    printf("Clave encontrada: %li\n", key);
    return 1;
  }
  
  return 0;
}

/**
 * Función para guardar un texto en un archivo
 * 
 * @param filename Nombre del archivo
 * @param text Texto a guardar
 * @param length Longitud del texto
 * 
 * @return 1 si se guardó correctamente, 0 si hubo un error
 */
int saveTextToFile(const char *filename, char *text, int length) {
    FILE *file = fopen(filename, "w"); // Se abre el archivo en modo escritura
    // Se verifica si hubo un error al abrir el archivo
    if (file == NULL) {
        perror("Error opening file");
        return 0;
    }

    fwrite(text, 1, length, file); // Se escribe el texto en el archivo
    fclose(file); // Se cierra el archivo

    // Se retorna 1 para indicar que se guardó correctamente
    return 1;
}

/**
 * Función principal
 * 
 * @param argc Cantidad de argumentos
 * @param argv Argumentos
 * 
 * @return 0 si se ejecutó correctamente, 1 si hubo un error
 */
int main(int argc, char *argv[]) {
    long upper = (1L << 56); // Límite superior para claves DES: 2^56
    long lower = 0; // Límite inferior para claves DES: 0
    long encryptionKey = 123456L; // Clave de encriptación por defecto
    char *text; // Texto a encriptar
    int textLength; // Longitud del texto a encriptar

    clock_t start_time, end_time; // Variables para medir el tiempo

    // Parseo de argumento para la llave
    int option;
    while ((option = getopt(argc, argv, "k:")) != -1) {
        switch (option) {
        // Si se obtiene una bandera -k se obtiene la llave de encriptación
        case 'k':
            encryptionKey = atol(optarg);
            break;
        // Si se obtiene una bandera no reconocida se muestra un mensaje de uso
        default:
            fprintf(stderr, "Usage: %s [-k key]\n", argv[0]);
            exit(1);
        }
    }

    // Leer el texto desde el archivo input.txt
    if (!loadTextFromFile("input.txt", &text, &textLength)) {
        return 1;
    }

    // Aplicar padding si es necesario en el mensaje
    int padding = 8 - (textLength % 8);
    if (padding < 8) {
        memset(text + textLength, padding, padding);
        textLength += padding;
    }

    printf("Texto a encriptar: %s\n", text); // Mostrar el texto a encriptar
    printf("Llave de encriptación: %li\n", encryptionKey); // Mostrar la llave de encriptación

    // Comenzamos a medir el tiempo
    start_time = clock();

    // Encriptar el texto
    encrypt(encryptionKey, text, textLength);
    
    // Guardar el texto encriptado
    if (!saveTextToFile("encrypted.txt", text, textLength)) {
        free(text);
        return 1;
    }

    // Recorremos de manera secuencial las claves DES posibles
    for (int i = lower; i < upper; ++i) {
        if (tryKey(i, text, textLength)) {
            // Desencriptar el texto
            decrypt(i, text, textLength);

            // Terminar la medición de tiempo
            end_time = clock();

            // Mostrar el mensaje desencriptado y el tiempo
            printf("Mensaje desencriptado: %s\n", text);
            printf("Tiempo tomado para desencriptar: %f segundos\n", ((double)(end_time - start_time)) / CLOCKS_PER_SEC);

            // Guardar el texto desencriptado en un archivo
            if (!saveTextToFile("decrypted.txt", text, textLength)) {
                free(text);
                return 1;
            }
        }
    }

    // Terminamos la medicion de tiempo
    end_time = clock();

    // Liberamos la memoria del texto
    free(text);

    // Retornamos 0 para indicar que se ejecutó correctamente
    return 0;
}