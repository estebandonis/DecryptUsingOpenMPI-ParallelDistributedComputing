/*
  Universidad del Valle de Guatemala
  Computación paralela y distribuida
  Proyecto#2

  Integrantes:
  Abner Iván García Alegría 21285
  Oscar Esteban Donis Martínez 21610
  Dariel Eduardo Villatoro 20776

  Archivo: doublesearch.c

  Proposito: Implementa un algoritmo de fuerza bruta para poder decifrar una 
             frase cifrada con el algoritmo DES de manera paralela revisando multiples valores a la vez.

  - Compilación: mpicc -o doublesearch doublesearch.c -lcrypto -lssl -w
  - Ejecución: mpirun -np 4 ./doublesearch -k <llave>
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>

/**
 * Función para desencriptar un texto cifrado con DES
 * 
 * @param key Clave de encriptación
 * @param ciph Texto cifrado
 * @param len Longitud del texto cifrado
 */
void decrypt(long key, char *ciph, int len) {
    // printf("Decrypting with key: %ld\n", key);

    DES_cblock key_block;
    DES_key_schedule schedule;

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
  char temp[len+1];
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, len);
  
  // Busca la cadena " the " en el texto desencriptado
  if (strstr((char *)temp, search) != NULL) {
    printf("Clave encontrada: %li\n", key);
    return 1;
  }
  
  return 0;
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
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    perror("Error al abrir el archivo");
    return 0;
  }

  // Determina la longitud del archivo
  fseek(file, 0, SEEK_END);
  *length = ftell(file);
  fseek(file, 0, SEEK_SET);

  // Asigna memoria para el texto basado en la longitud del archivo
  *text = (char *)malloc(*length);
  if (*text == NULL) {
    perror("Error de asignación de memoria");
    fclose(file);
    return 0;
  }

  // Lee el contenido del archivo en el texto
  fread(*text, 1, *length, file);
  fclose(file);

  return 1;
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
  FILE *file = fopen(filename, "w");
  if (file == NULL) {
    perror("Error al abrir el archivo");
    return 0;
  }

  // Escribe el contenido del texto en el archivo
  fwrite(text, 1, length, file);
  fclose(file);

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
int main(int argc, char *argv[]){
  int N, id;
  long upper = (1L << 56); // Límite superior para claves DES: 2^56
  long mylower, myupper;
  MPI_Status st;
  MPI_Request req;
  int flag;
  MPI_Comm comm = MPI_COMM_WORLD;

  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  clock_t start_time_C, end_time_C;
  double start_time, end_time; // Variables para medir el tiempo de ejecución
  long encryptionKey = 123456L; // Valor predeterminado para la clave de encriptación

  int option;

  // Procesa las opciones de la línea de comandos
  while ((option = getopt(argc, argv, "k:")) != -1) {
    switch (option) {
      case 'k':
        encryptionKey = atol(optarg);
        break;
      default:
        fprintf(stderr, "Uso: %s [-k key]\n", argv[0]);
        MPI_Finalize();
        exit(1);
    }
  }

  start_time_C = clock();

  // Inicia el contador de tiempo
  start_time = MPI_Wtime();

  // Calcula el rango de claves que cada proceso MPI debe buscar
  long range_per_node = upper / N;
  mylower = range_per_node * id;
  myupper = range_per_node * (id+1) - 1;
  if (id == N - 1) {
    // Compensar el residuo
    myupper = upper;
  }

  char *text; // Texto para encriptar y desencriptar
  int textLength;

  if (id == 0) {
    // Carga el texto desde un archivo (por ejemplo, "input.txt")
    if (!loadTextFromFile("input.txt", &text, &textLength)) {
      MPI_Finalize();
      return 1;
    }

    encrypt(encryptionKey, text, textLength);

    // Guarda el texto encriptado en un archivo (por ejemplo, "encrypted.txt")
    if (!saveTextToFile("encrypted.txt", text, textLength)) {
      free(text);
      MPI_Finalize();
      return 1;
    }
  }

  // Difunde el texto encriptado a todos los nodos
  MPI_Bcast(&textLength, 1, MPI_INT, 0, comm);
  if (id != 0) {
    text = (char *)malloc(textLength);
  }
  MPI_Bcast(text, textLength, MPI_CHAR, 0, comm);

  long found = 0;

  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

  long left_edge = mylower;
  long left_side = (mylower + myupper) / 2;
  long right_side = left_side + 1;
  long right_edge = myupper;

  // Distribuye el trabajo entre los nodos 
  while (left_side >= left_edge && right_side <= right_edge && (found == 0)) {
    // Busca la clave en el lado izquierdo del rango
    if (tryKey(left_edge, text, textLength)) {
      found = left_edge;
      for (int node = 0; node < N; node++) {
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }

    if (tryKey(left_side, text, textLength)) {
      found = left_side;
      for (int node = 0; node < N; node++) {
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }

    // Busca la clave en el lado derecho del rango
    if (tryKey(right_edge, text, textLength)) {
      found = right_edge;
      for (int node = 0; node < N; node++) {
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }

    if (tryKey(right_side, text, textLength)) {
      found = right_side;
      for (int node = 0; node < N; node++) {
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }

    left_edge++;
    left_side--;
    right_side++;
    right_edge--;

    MPI_Test(&req, &flag, &st);
    if (flag) {  // Si se ha encontrado la clave por otro proceso
      break;
    }
  }

  if (id == 0) {
    MPI_Wait(&req, &st);
    decrypt(found, text, textLength);

    // Termina el contador de tiempo
    end_time = MPI_Wtime();
    end_time_C = clock();

    // Imprime el texto desencriptado y la clave de encriptación
    printf("Tiempo de ejecución MPI: %f segundos\n", end_time - start_time);

    // Calcula el tiempo transcurrido
    double execution_time = (double)(end_time_C - start_time_C) / CLOCKS_PER_SEC;

    // Imprime el tiempo de ejecución en segundos
    printf("Tiempo de ejecución: %f segundos\n", execution_time);

    // Guarda el texto desencriptado en un archivo (por ejemplo, "decrypted.txt")
    if (!saveTextToFile("decrypted.txt", text, textLength)) {
      free(text);
      MPI_Finalize();
      return 1;
    }
  }

  free(text);

  MPI_Finalize();
}