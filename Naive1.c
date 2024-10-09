/*
  Universidad del Valle de Guatemala
  Computación paralela y distribuida
  Proyecto#2

  Integrantes:
  Abner Iván García Alegría 21285
  Oscar Esteban Donis Martínez 21610
  Dariel Eduardo Villatoro 20776
   
  - Compilación: mpicc -o distributed distributed.c -lcrypto -lssl -w
  - Ejecución: mpirun -np 4 ./distributed -k <llave>
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi/mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <ctype.h>
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

int tryKeys(long lower, long upper, char *ciph, int len) {
  for (long key = lower; key <= upper; key++) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);
    if (strstr((char *)temp, search) != NULL) {
      printf("Clave encontrada: %li\n", key);
      return key;
    }
  }
  return -1; // Indicar que no se encontró la clave
}

int main(int argc, char *argv[]) {
  int N, id;
  long upper = (1L << 56);
  MPI_Status st;
  int found = 0;
  MPI_Comm comm = MPI_COMM_WORLD;

  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  clock_t start_time_C, end_time_C;
  double start_time, end_time;
  long encryptionKey = 123456L;

  int option;
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
  start_time = MPI_Wtime();

  int range_per_node = upper / N;
  long mylower = range_per_node * id;
  long myupper = range_per_node * (id + 1) - 1;
  if (id == N - 1) {
    myupper = upper;
  }

  char *text;
  int textLength;

  if (id == 0) {
    if (!loadTextFromFile("input.txt", &text, &textLength)) {
      MPI_Finalize();
      return 1;
    }
    encrypt(encryptionKey, text, textLength);
    if (!saveTextToFile("encrypted.txt", text, textLength)) {
      free(text);
      MPI_Finalize();
      return 1;
    }
  }

  MPI_Bcast(&textLength, 1, MPI_INT, 0, comm);
  if (id != 0) {
    text = (char *)malloc(textLength);
  }
  MPI_Bcast(text, textLength, MPI_CHAR, 0, comm);

  if (id == 0) {
    long keyRange[N][2];
    for (int i = 0; i < N; i++) {
      keyRange[i][0] = range_per_node * i;
      keyRange[i][1] = range_per_node * (i + 1) - 1;
      if (i == N - 1) {
        keyRange[i][1] = upper;
      }
    }

    for (int i = 1; i < N; i++) {
      MPI_Send(&keyRange[i], 2, MPI_LONG, i, 0, comm);
    }

    for (int i = 1; i < N; i++) {
      MPI_Recv(&found, 1, MPI_LONG, i, 0, comm, &st);
      if (found != -1) {
        break;
      }
    }

    if (found != -1) {
      decrypt(found, text, textLength);
      end_time = MPI_Wtime();
      end_time_C = clock();
      printf("Tiempo de ejecución MPI: %f segundos\n", end_time - start_time);
      double execution_time = (double)(end_time_C - start_time_C) / CLOCKS_PER_SEC;
      printf("Tiempo de ejecución: %f segundos\n", execution_time);
      if (!saveTextToFile("decrypted.txt", text, textLength)) {
        free(text);
        MPI_Finalize();
        return 1;
      }
    }
  } else {
    long keyRange[2];
    MPI_Recv(&keyRange, 2, MPI_LONG, 0, 0, comm, &st);
    found = tryKeys(keyRange[0], keyRange[1], text, textLength);
    MPI_Send(&found, 1, MPI_LONG, 0, 0, comm);
  }

  free(text);
  MPI_Finalize();
}