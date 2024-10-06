#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>

/**
 * @brief Función que descifra un bloque de 64 bits usando el algoritmo DES
 * y luego compara con la palabra que conocemos si es la clave o no.
 * 
 * @param plaintext Texto claro de 64 bits.
 * @param key Clave de 64 bits.
 * @param ciphertext Texto cifrado de 64 bits.
 */
void des_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    // Estructura que almacena la clave DES
    DES_key_schedule schedule;
    // Estructura que lleva un registro de las claves utilizadas
    DES_set_key_unchecked((const_DES_cblock *)key, &schedule);
    // Funcion que desencripta un bloque de 64 bits y lo guarda en ciphertext
    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}

/**
 * @brief Función principal que prueba todas las claves posibles de 56 y 64 bits
 * para descifrar un texto cifrado y verificar si coincide con una palabra clave conocida.
 * 
 * @return int 
 */
int main() {
    // Inicializar variables de tiempo y uso de CPU
    clock_t start, end;
    double cpu_time_used;
    // Texto cifrado de 64 bits
    unsigned char ciphertext[8] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    // Palabra clave conocida
    char* known_keyword = "tu_palabra_clave";
    // Longitudes de clave DES válidas en bits
    int key_lengths[] = {56, 64};
    // Probar todas las longitudes de clave
    for (int i = 0; i < sizeof(key_lengths) / sizeof(key_lengths[0]); i++) {
        // Longitud de la clave en bytes
        int key_length = key_lengths[i] / 8;
        // Inicializar la clave a 0
        unsigned char key[8] = {0};
        // Iniciar el cronómetro
        start = clock();
        // Probar todas las claves posibles de la longitud actual
        for (unsigned long long candidate = 0; candidate < (1ULL << (key_lengths[i])); candidate++) {
            // Copiar la clave candidata en el buffer de la clave
            memcpy(key, &candidate, key_length);
            // Buffer para almacenar el texto descifrado
            unsigned char decrypted_text[8];
            // Descifrar el texto cifrado con la clave candidata
            des_encrypt(ciphertext, key, decrypted_text);
            // Imprimir información sobre la clave que se está probando
            printf("Probando clave: ");
            for (int j = 0; j < key_length; j++) {
                printf("%02X", key[j]);
            }
            printf("\n");
            // Verificar si el texto descifrado coincide con el texto conocido
            if (memcmp(decrypted_text, known_keyword, strlen(known_keyword)) == 0) {
                // Detener el cronómetro
                end = clock();
                // Calcular el tiempo transcurrido
                cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
                // Imprimir la clave encontrada correcta
                printf("Clave encontrada: ");
                for (int j = 0; j < key_length; j++) {
                    printf("%02X", key[j]);
                }
                // Imprimir el tiempo transcurrido
                printf(" en %.2lf segundos para clave de %d bits.\n", cpu_time_used, key_lengths[i]);
                // Salir del bucle si se encuentra la clave correcta
                break;
            }
        }
    }
    // Salir del programa
    return 0;
}