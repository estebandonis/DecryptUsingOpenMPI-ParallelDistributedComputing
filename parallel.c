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
 * Archivo:     parallel.c
 * 
 * Propósito:   Implementa un algoritmo de fuerza bruta para poder decifrar una 
 *              frase cifrada con el algoritmo DES de manera secuencial.
 *
 * Compile:     mpicc -o parallel parallel.c -lcrypto
 * Run:         mpiexec -np <comm_sz> ./parallel <args>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <mpi.h>
#include <time.h>

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
 * @param text      Texto sin cifrar
 * @param ciph      Puntero a texto cifrado
 * @param len       Longitud del texto cifrado
 * 
 * @return void
 */
void encrypt(uint64_t key, unsigned char *text, unsigned char *ciph, int len){
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
    DES_ecb_encrypt((DES_cblock *)text, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

/**
 * Función para probar una clave
 * 
 * @param key       Clave a probar
 * @param ciph      Texto cifrado
 * @param len       Longitud del texto cifrado
 * 
 * @return int
 */
int tryKey(uint64_t key, unsigned char *ciph, int len, const char* search){
    unsigned char temp[len + 1];
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

/**
 * Función principal
 * 
 * @param argc      Cantidad de argumentos
 * @param argv      Argumentos
 * 
 * @return int
 */
int main(int argc, char *argv[]){

    if (argc < 3) {
        printf("Uso: \n");
        printf("%s -e <archivo> <clave> para cifrar\n", argv[0]);
        printf("%s -d <archivo> <fragmento> para descifrar\n", argv[0]);
        return 1;
    }

    FILE *input_file = fopen(argv[2], "rb");
    if (!input_file) {
        printf("Error al abrir el archivo %s\n", argv[1]);
        return 1;
    }

    // Determinar el tamaño del archivo
    fseek(input_file, 0, SEEK_END);
    long fsize = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    unsigned char *buffer = malloc(fsize + 1);
    fread(buffer, 1, fsize, input_file);
    fclose(input_file);

    if (strcmp(argv[1], "-e") == 0) {
        // Cifrar el archivo
        uint64_t key = strtoull(argv[3], NULL, 10);

        unsigned char *ciph = malloc(fsize + 1);
        encrypt(key, buffer, ciph, fsize);
        ciph[fsize] = '\0';

        char output_filename[256];
        snprintf(output_filename, sizeof(output_filename), "%s.ciph", argv[2]);

        FILE *output_file = fopen(output_filename, "wb");
        fwrite(ciph, 1, fsize, output_file);
        fclose(output_file);
        free(ciph);
    } else
    if (strcmp(argv[1], "-d") == 0) {
        unsigned char *cipher = buffer;
        const char *search = argv[3];

        printf("%s", search);
        return 0;

        int N, id;
        // Usar uint64_t para asegurar 64 bits
        uint64_t upper = ((uint64_t)1 << 56); // límite superior de claves DES 2^56
        uint64_t mylower, myupper;
        MPI_Status st;
        MPI_Request req;
        int flag;
        // Determinar la longitud del texto cifrado
        // Dado que 'cipher' puede contener '\0', usa sizeof
        // int ciphlen = sizeof(cipher) - 1; // Excluir el terminador nulo si está presente
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
            if(tryKey(i, cipher, fsize, search)){
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
            unsigned char decrypted[fsize + 1];
            memcpy(decrypted, cipher, fsize);
            decrypted[fsize] = '\0';
            decrypt(found, decrypted, fsize);
            printf("Clave encontrada: %lu\nTexto descifrado: %s\n", found, decrypted);
        }

        MPI_Finalize();
    }

    free(buffer);

    return 0;
}