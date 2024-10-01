#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>
void des_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}
int main() {
    unsigned char ciphertext[8] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    char* known_keyword = "tu_palabra_clave";
    int key_lengths[] = {56, 64};  // Longitudes de clave DES válidas en bits
    for (int i = 0; i < sizeof(key_lengths) / sizeof(key_lengths[0]); i++) {
        int key_length = key_lengths[i] / 8;  // Convertir bits a bytes
        unsigned char key[8] = {0};  // Inicializar la clave a 0
        clock_t start, end;
        double cpu_time_used;
        start = clock();  // Iniciar el cronómetro
        for (unsigned long long candidate = 0; candidate < (1ULL << (key_lengths[i])); candidate++) {
            memcpy(key, &candidate, key_length);
            unsigned char decrypted_text[8];
            des_encrypt(ciphertext, key, decrypted_text);
            // Imprimir información sobre la clave que se está probando
            printf("Probando clave: ");
            for (int j = 0; j < key_length; j++) {
                printf("%02X", key[j]);
            }
            printf("\n");
            // Verificar si el texto descifrado coincide con el texto claro conocido
            if (memcmp(decrypted_text, known_keyword, strlen(known_keyword)) == 0) {
                end = clock();  // Detener el cronómetro
                cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;  // Calcular el tiempo transcurrido
                printf("Clave encontrada: ");
                for (int j = 0; j < key_length; j++) {
                    printf("%02X", key[j]);
                }
                printf(" en %.2lf segundos para clave de %d bits.\n", cpu_time_used, key_lengths[i]);
                break;  // Salir del bucle si se encuentra la clave
            }
        }
    }
    return 0;
}