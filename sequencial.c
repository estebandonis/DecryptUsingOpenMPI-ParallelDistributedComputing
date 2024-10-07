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

char search[] = "es una prueba de";

int tryKey(long key, char *ciph, int len) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);

    if (strstr((char *)temp, search) != NULL) {
        printf("Key found: %li\n", key);
        return 1;
    }

    return 0;
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

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

int main(int argc, char *argv[]) {
    long upper = (1L << 56);
    long mylower = 0;
    long myupper = upper;
    char *text;
    int textLength;

    clock_t start_time, end_time;
    long encryptionKey = 123456L;

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

    start_time = clock();

    if (!loadTextFromFile("input.txt", &text, &textLength)) {
        return 1;
    }

    // aplicar padding
    int padding = 8 - (textLength % 8);
    if (padding < 8) {
        memset(text + textLength, padding, padding);
        textLength += padding;
    }

    encrypt(encryptionKey, text, textLength);

    if (!saveTextToFile("encrypted.txt", text, textLength)) {
        free(text);
        return 1;
    }

    free(text);

    long found = 0;

    for (long i = mylower; i < myupper && (found == 0); ++i) {
        if (tryKey(i, text, textLength)) {
            found = i;
            break;
        }
    }

    end_time = clock();

    text = (char *)malloc(textLength);
    if (!loadTextFromFile("encrypted.txt", &text, &textLength)) {
        free(text);
        return 1;
    }

    decrypt(found, text, textLength);

    printf("%li %s\n", found, text);
    printf("Execution time: %f seconds\n", ((double)(end_time - start_time)) / CLOCKS_PER_SEC);

    if (!saveTextToFile("decrypted.txt", text, textLength)) {
        free(text);
        return 1;
    }

    free(text);

    return 0;
}