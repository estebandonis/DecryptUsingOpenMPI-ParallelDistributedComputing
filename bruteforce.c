/*
  Universidad del Valle de Guatemala
  Computación paralela y distribuida
  Proyecto#2

  Integrantes:
  Abner Iván García Alegría 21285
  Oscar Esteban Donis Martínez 21610
  Dariel Eduardo Villatoro 20776

  Archivo: bruteforce.c

  Proposito: Implementa un algoritmo de fuerza bruta para poder decifrar una 
             frase cifrada con el algoritmo DES de manera paralela.

  - Compilación: mpicc -o bruteforce bruteforce.c -lcrypto -lssl -w
  - Ejecución: mpirun -np 4 ./bruteforce -k <llave>
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi/mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>
#include <time.h>

/**
 * Función para desencriptar un texto cifrado con DES
 * 
 * @param key Clave de encriptación
 * @param ciph Texto cifrado
 * @param len Longitud del texto cifrado
 */
void decrypt(long key, char *ciph, int len) {
    // printf("Decrypting with key: %ld\n", key);

    DES_cblock key_block; // Bloque de clave DES
    DES_key_schedule schedule; // Horario de clave DES

    // Inicializa el bloque de clave DES con ceros
    memset(key_block, 0, sizeof(DES_cblock));
    // Copia la clave proporcionada en el bloque de clave
    memcpy(key_block, &key, sizeof(long));

    // Crea un horario de clave DES basado en la clave
    DES_set_key_unchecked(&key_block, &schedule);

    // Realiza una desencriptación DES en el texto cifrado
    for (int i = 0; i < len; i += 8) {
        // printf("Decrypting block %d\n", i/8);
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
void encrypt(long key, char *ciph, int len){
    // printf("Encrypting with key: %ld\n", key);

    DES_cblock key_block;
    DES_key_schedule schedule;

    // Inicializa el bloque de clave DES con ceros
    memset(key_block, 0, sizeof(DES_cblock));
    // Copia la clave proporcionada en el bloque de clave
    memcpy(key_block, &key, sizeof(long));
  
    // Crea un horario de clave DES basado en la clave
    DES_set_key_unchecked(&key_block, &schedule);
    // Realiza una encriptación DES en el texto
    for (int i = 0; i < len; i += 8) {
        // printf("Encrypting block %d\n", i/8);
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }
}

char search[] = "es una prueba de"; // Cadena a buscar en el texto desencriptado

/**
 * Función para encriptar un texto con DES
 * 
 * @param key Clave de encriptación
 * @param ciph Texto a encriptar
 * @param len Longitud del texto a encriptar
 */
int tryKey(long key, char *ciph, int len){
  char temp[len+1]; // Texto temporal para almacenar el texto desencriptado
  memcpy(temp, ciph, len); // Copia el texto cifrado en el texto temporal
  temp[len]=0; // Agrega un carácter nulo al final del texto temporal
  decrypt(key, temp, len); // Desencripta el texto temporal con la clave proporcionada
  
  // Busca la cadena " the " en el texto desencriptado
  if (strstr((char *)temp, search) != NULL) {
    return 1; // Si se encuentra la cadena, retorna 1
  }
  
  return 0; // Si no se encuentra la cadena, retorna 0
}

/**
 * Función para cargar un texto desde un archivo
 * 
 * @param filename Nombre del archivo
 * @param text Puntero a la variable texto donde cargar el contenido
 * @param length Longitud del texto cargado
 * @return 1 si se cargó correctamente, 0 si hubo un error
 */
// Función para cargar un texto desde un archivo
int loadTextFromFile(const char *filename, char **text, int *length) {
  FILE *file = fopen(filename, "r"); // Abre el archivo en modo de lectura
  if (file == NULL) {
    perror("Error al abrir el archivo"); // Imprime un mensaje de error si no se pudo abrir el archivo
    return 0; // Retorna 0 si hubo un error
  }

  // Determina la longitud del archivo
  fseek(file, 0, SEEK_END);
  *length = ftell(file); // Obtiene la posición actual en el archivo
  fseek(file, 0, SEEK_SET); // Establece la posición actual en el archivo

  // Asigna memoria para el texto basado en la longitud del archivo
  *text = (char *)malloc(*length);
  if (*text == NULL) {
    perror("Error de asignación de memoria"); // Imprime un mensaje de error si no se pudo asignar memoria
    fclose(file); // Cierra el archivo
    return 0; // Retorna 0 si hubo un error
  }

  // Lee el contenido del archivo en el texto
  fread(*text, 1, *length, file);
  fclose(file); // Cierra el archivo

  return 1; // Retorna 1 si se cargó correctamente
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
  FILE *file = fopen(filename, "w"); // Abre el archivo en modo de escritura
  if (file == NULL) {
    perror("Error al abrir el archivo"); // Imprime un mensaje de error si no se pudo abrir el archivo
    return 0; // Retorna 0 si hubo un error
  }

  // Escribe el contenido del texto en el archivo
  fwrite(text, 1, length, file);
  fclose(file); // Cierra el archivo

  return 1; // Retorna 1 si se guardó correctamente
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
    int N, id; // Variables para el número de procesos y el ID del proceso
    long upper = (1L << 56); // Límite superior para claves DES: 2^56
    long mylower, myupper; // Límite inferior y superior para claves DES
    MPI_Status st; // Estructura para el estado de la comunicación
    MPI_Request req; // Estructura para la solicitud de comunicación
    int flag; // Bandera para la solicitud de comunicación
    MPI_Comm comm = MPI_COMM_WORLD; // Comunicador MPI predeterminado

    MPI_Init(NULL, NULL); // Inicializa el entorno MPI
    MPI_Comm_size(comm, &N); // Obtiene el número de procesos
    MPI_Comm_rank(comm, &id); // Obtiene el ID del proceso

    clock_t start_time_C, end_time_C;
    double start_time, end_time; // Variables para medir el tiempo de ejecución
    long encryptionKey = 123456L; // Valor predeterminado para la clave de encriptación

    int option; // Opción de la línea de comandos

    // Procesa las opciones de la línea de comandos
    while ((option = getopt(argc, argv, "k:")) != -1) {
        switch (option) {
            case 'k': // Opción para la clave de encriptación
                encryptionKey = atol(optarg); // Convierte el argumento en un número
                break; // Sale del switch
            default:
                fprintf(stderr, "Uso: %s [-k key]\n", argv[0]); // Imprime un mensaje de uso
                MPI_Finalize(); // Finaliza el entorno MPI
                exit(1); // Sale del programa con código de error
        }
    }

    start_time_C = clock(); // Inicia el contador de tiempo en C
    start_time = MPI_Wtime(); // Inicia el contador de tiempo en MPI

    // Calcula el rango de claves que cada proceso MPI debe buscar
    long range_per_node = upper / N;
    mylower = range_per_node * id; // Límite inferior para el proceso actual
    myupper = range_per_node * (id + 1) - 1; // Límite superior para el proceso actual

    if (id == N - 1) {
        myupper = upper; // El último proceso recibe cualquier residuo
    }

    char *text; // Texto a encriptar/desencriptar
    int textLength; // Longitud del texto a encriptar/desencriptar

    // Carga el texto desde un archivo y lo encripta
    if (id == 0) {
        if (!loadTextFromFile("input.txt", &text, &textLength)) {
            MPI_Finalize();
            return 1;
        }
        // Encripta el texto con la clave proporcionada
        encrypt(encryptionKey, text, textLength);
        // Guarda el texto encriptado en un archivo
        if (!saveTextToFile("encrypted.txt", text, textLength)) {
            free(text); // Libera la memoria del texto
            MPI_Finalize(); // Finaliza el entorno MPI
            return 1; // Retorna 1 si hubo un error
        }
    }

    MPI_Bcast(&textLength, 1, MPI_INT, 0, comm); // Difunde la longitud del texto
    if (id != 0) {
        text = (char *)malloc(textLength); // Asigna memoria para el texto
    }
    MPI_Bcast(text, textLength, MPI_CHAR, 0, comm); // Difunde el texto

    long found = 0; // Clave encontrada
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req); // Recibe la clave encontrada

    // Búsqueda comenzando desde el límite inferior
    for (long i = mylower; i <= myupper && found == 0; i++) {
        if (tryKey(i, text, textLength)) {
            found = i;

            // Notificar a todos los procesos que se ha encontrado la clave
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, comm); // Envía la clave encontrada
            }

            break; // Sale del bucle si se ha encontrado la clave
        }

        MPI_Test(&req, &flag, &st); // Verifica si se ha encontrado la clave por otro proceso
        if (flag) {  // Si se ha encontrado la clave por otro proceso
            break; // Sale del bucle
        }
    }
    // Si se ha encontrado la clave, espera a que todos los procesos reciban la clave
    if (id == 0) {
        MPI_Wait(&req, &st); // Espera a que todos los procesos reciban la clave
        decrypt(found, text, textLength); // Desencripta el texto con la clave encontrada

        end_time = MPI_Wtime(); // Finaliza el contador de tiempo en MPI
        end_time_C = clock(); // Finaliza el contador de tiempo en C

        printf("Clave encontrada: %ld\n", found); // Imprime la clave encontrada
        printf("Mensaje desencriptado: %s\n", text); // Imprime el mensaje desencriptado
        printf("Tiempo de ejecución MPI: %f segundos\n", end_time - start_time); // Imprime el tiempo de ejecución en MPI
        double execution_time = (double)(end_time_C - start_time_C) / CLOCKS_PER_SEC; // Calcula el tiempo de ejecución en C
        printf("Tiempo de ejecución: %f segundos\n", execution_time); // Imprime el tiempo de ejecución en C

        if (!saveTextToFile("decrypted.txt", text, textLength)) {
            free(text); // Libera la memoria del texto
            MPI_Finalize(); // Finaliza el entorno MPI
            return 1; // Retorna 1 si hubo un error
        }
    }

    free(text); // Libera la memoria del texto
    MPI_Finalize(); // Finaliza el entorno MPI
}
