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
 * Archivo:     bruteforce.c
 * 
 * Propósito:   Implementa un algoritmo de fuerza bruta para poder decifrar una 
 *              frase cifrada con el algoritmo DES de manera paralela.
 *
 * Compile:     mpicc -o bruteforce bruteforce.c -lcrypto
 * Run:         mpiexec -n <comm_sz> ./bruteforce
 */

// bruteforce.c
// Nota: El key usado es bastante pequeño, cuando sea random speedup variará

// Incluimos las librerías necesarias
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <stdint.h>
#include <openssl/des.h>

/**
 * Función para descifrar usando OpenSSL DES
 * 
 * @param key       Clave para descifrar
 * @param ciph      Texto cifrado
 * @param len       Longitud del texto cifrado
 * 
 * @return void
 */
void decrypt(uint64_t key, unsigned char *ciph, int len){
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir el key de uint64_t a 8 bytes (big endian)
    for(int i = 0; i < 8; ++i){
        key_block[i] = (key >> (56 - i*8)) & 0xFF;
    }

    // Establecer la paridad
    DES_set_odd_parity(&key_block);

    // Configurar el calendario de claves
    if (DES_set_key_checked(&key_block, &schedule) != 0) {
        // Clave inválida; posiblemente todos los bits de un byte son iguales
        // Puedes optar por ignorar estas claves en lugar de salir
        return;
    }

    // Realizar el descifrado en modo ECB
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

/**
 * Función para cifrar usando OpenSSL DES (si es necesario)
 * 
 * @param key       Clave para cifrar
 * @param ciph      Texto cifrado
 * @param len       Longitud del texto cifrado
 * 
 * @return void
 */
void encrypt(uint64_t key, unsigned char *ciph, int len){
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir el key de uint64_t a 8 bytes (big endian)
    for(int i = 0; i < 8; ++i){
        key_block[i] = (key >> (56 - i*8)) & 0xFF;
    }

    // Establecer la paridad
    DES_set_odd_parity(&key_block);

    // Configurar el calendario de claves
    if (DES_set_key_checked(&key_block, &schedule) != 0) {
        // Clave inválida
        return;
    }

    // Realizar el cifrado en modo ECB
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

const char search[] = " the ";
/**
 * Función para probar una clave
 * 
 * @param key       Clave a probar
 * @param ciph      Texto cifrado
 * @param len       Longitud del texto cifrado
 * 
 * @return int
 */
int tryKey(uint64_t key, unsigned char *ciph, int len){
    unsigned char temp[len];
    memcpy(temp, ciph, len);
    printf("Probando clave: %lu\n", key);
    decrypt(key, temp, len);
    // Asegurar que 'temp' esté terminada en '\0' si se busca una cadena
    // Asegúrate de que 'temp' no tenga bytes nulos intermedios
    // Esto puede no ser seguro si el texto descifrado contiene '\0'
    // Considera usar otra técnica de verificación
    temp[len] = '\0'; // Agrega un byte adicional para la terminación
    return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

/**
 * Función principal
 * 
 * @param argc      Cantidad de argumentos
 * @param argv      Argumentos
 * 
 * @return int
 */
int main(int argc, char *argv[]){
    int N, id;
    // Usar uint64_t para asegurar 64 bits
    uint64_t upper = ((uint64_t)1 << 56); // límite superior de claves DES 2^56
    uint64_t mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    int flag;
    // Determinar la longitud del texto cifrado
    // Dado que 'cipher' puede contener '\0', usa sizeof
    int ciphlen = sizeof(cipher) - 1; // Excluir el terminador nulo si está presente
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    uint64_t range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id+1) -1;
    if(id == N-1){
        // Compensar residuo
        myupper = upper -1;
    }

    uint64_t found = 0;

    // Iniciar una recepción no bloqueante para 'found'
    MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    for(uint64_t i = mylower; i <= myupper && (found == 0); ++i){
        if(tryKey(i, cipher, ciphlen)){
            found = i;
            // Enviar la clave encontrada a todos los nodos
            for(int node = 0; node < N; node++){
                MPI_Send(&found, 1, MPI_UNSIGNED_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }
        // Opcional: Puedes verificar periódicamente si 'found' ha sido actualizado por otro nodo
        MPI_Test(&req, &flag, &st);
        if(flag && found != 0){
            break;
        }
    }

    // Esperar a que cualquier mensaje pendiente sea recibido
    MPI_Wait(&req, &st);

    if(id == 0 && found != 0){
        unsigned char decrypted[ciphlen + 1];
        memcpy(decrypted, cipher, ciphlen);
        decrypted[ciphlen] = '\0';
        decrypt(found, decrypted, ciphlen);
        printf("Clave encontrada: %lu\nTexto descifrado: %s\n", found, decrypted);
    }

    MPI_Finalize();
    return 0;
}