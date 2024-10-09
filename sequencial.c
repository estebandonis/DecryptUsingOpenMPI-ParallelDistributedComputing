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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/des.h>
#include <time.h>

void decrypt(long key, char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    memset(key_block, 0, sizeof(DES_cblock));
    memcpy(key_block, &key, sizeof(long));

    DES_set_key_unchecked(&key_block, &schedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }
}

void encrypt(long key, char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    memset(key_block, 0, sizeof(DES_cblock));
    memcpy(key_block, &key, sizeof(long));

    DES_set_key_unchecked(&key_block, &schedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }
}

int loadTextFromFile(const char *filename, char **text, int *length) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 0;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    *text = (char *)malloc(*length);
    if (*text == NULL) {
        perror("Memory allocation error");
        fclose(file);
        return 0;
    }

    fread(*text, 1, *length, file);
    fclose(file);

    return 1;
}

char search[] = "es una prueba de";

int tryKey(long key, char *ciph, int len){
  char temp[len+1];
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, len);
  
  if (strstr((char *)temp, search) != NULL) {
    printf("Clave encontrada: %li\n", key);
    return 1;
  }
  
  return 0;
}

int saveTextToFile(const char *filename, char *text, int length) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return 0;
    }

    fwrite(text, 1, length, file);
    fclose(file);

    return 1;
}

int main(int argc, char *argv[]) {
    long upper = (1L << 56); // Límite superior para claves DES: 2^56
    long lower = 0;
    long encryptionKey = 123456L;
    char *text;
    int textLength;

    clock_t start_time, end_time;

    // Parseo de argumento para la llave
    int option;
    while ((option = getopt(argc, argv, "k:")) != -1) {
        switch (option) {
        case 'k':
            encryptionKey = atol(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-k key]\n", argv[0]);
            exit(1);
        }
    }

    // Leer el texto desde el archivo input.txt
    if (!loadTextFromFile("input.txt", &text, &textLength)) {
        return 1;
    }

    // Aplicar padding si es necesario
    int padding = 8 - (textLength % 8);
    if (padding < 8) {
        memset(text + textLength, padding, padding);
        textLength += padding;
    }

    printf("Texto a encriptar: %s\n", text);
    printf("Llave de encriptación: %li\n", encryptionKey);

    // Medir el tiempo de desencriptación
    start_time = clock();

    // Encriptar el texto
    encrypt(encryptionKey, text, textLength);
    
    // Guardar el texto encriptado
    if (!saveTextToFile("encrypted.txt", text, textLength)) {
        free(text);
        return 1;
    }

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
            break;
        }
    }

    end_time = clock();

    free(text);

    return 0;
}