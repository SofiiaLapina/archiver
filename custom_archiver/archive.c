/**
 * @file archive.c
 * @brief Файл реалізації функцій архівування, шифрування та розархівації.
 */

#include "archive.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir _mkdir
#define PATH_SEPARATOR '\\'
#else
#include <unistd.h>
#define PATH_SEPARATOR '/'
#endif

#define BUFFER_SIZE 8192
#define IV_SIZE 16
#define HASH_SIZE 32

/**
 * @brief Додає файл до архіву.
 * 
 * @param filepath Шлях до файлу для додавання.
 * @param base_path Базовий шлях для файлу в архіві.
 * @param archive_file Вказівник на архівний файл.
 * @param key Ключ для шифрування файлу.
 * @return int Повертає 0 при успіху, інше значення при помилці.
 */
static int add_file(const char *filepath, const char *base_path, FILE *archive_file, const unsigned char *key);

/**
 * @brief Рекурсивно обробляє каталог і додає його вміст до архіву.
 * 
 * @param dirpath Шлях до каталогу.
 * @param base_path Базовий шлях для каталогу в архіві.
 * @param archive_file Вказівник на архівний файл.
 * @param key Ключ для шифрування файлів у каталозі.
 * @return int Повертає 0 при успіху, інше значення при помилці.
 */
static int process_directory(const char *dirpath, const char *base_path, FILE *archive_file, const unsigned char *key);

/**
 * @brief Створює архів з файлів та каталогів.
 * 
 * @param input_paths Масив шляхів до файлів або каталогів.
 * @param input_count Кількість файлів або каталогів.
 * @param output_path Шлях до вихідного архівного файлу.
 * @param key 256-бітний ключ для шифрування.
 * @return int Повертає 0 при успіху, інше значення при помилці.
 */
int create_archive(const char **input_paths, size_t input_count, const char *output_path, const unsigned char *key) {
    FILE *archive_file = fopen(output_path, "wb");
    if (!archive_file) {
        fprintf(stderr, "Failed to open output archive file.\n");
        return -1;
    }

    // Записуємо простий заголовок
    fwrite("CARCHIVE", 1, 8, archive_file);
    
    // Генеруємо та записуємо IV
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "Failed to generate IV.\n");
        fclose(archive_file);
        return -1;
    }
    fwrite(iv, 1, IV_SIZE, archive_file);

    // Додаємо кожен файл або директорію в архів
    for (size_t i = 0; i < input_count; ++i) {
        const char *path = input_paths[i];
        struct stat path_stat;
        if (stat(path, &path_stat) != 0) {
            fprintf(stderr, "Failed to stat %s\n", path);
            continue;
        }
        if (S_ISDIR(path_stat.st_mode)) {
            // Якщо це директорія, обробляємо її рекурсивно
            if (process_directory(path, basename((char *)path), archive_file, key) != 0) {
                fprintf(stderr, "Failed to add directory %s to archive.\n", path);
            }
        } else if (S_ISREG(path_stat.st_mode)) {
            // Якщо це файл, додаємо його в архів
            if (add_file(path, basename((char *)path), archive_file, key) != 0) {
                fprintf(stderr, "Failed to add file %s to archive.\n", path);
            }
        }
    }

    fclose(archive_file);
    return 0;
}

/**
 * @brief Додає файл до архіву.
 * 
 * @param filepath Шлях до файлу для додавання.
 * @param relative_path Відносний шлях файлу в архіві.
 * @param archive_file Вказівник на архівний файл.
 * @param key Ключ для шифрування файлу.
 * @return int Повертає 0 при успіху, інше значення при помилці.
 */
static int add_file(const char *filepath, const char *relative_path, FILE *archive_file, const unsigned char *key) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s\n", filepath);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *filedata = malloc(filesize);
    if (!filedata) {
        fprintf(stderr, "Memory allocation error.\n");
        fclose(fp);
        return -1;
    }
    fread(filedata, 1, filesize, fp);
    fclose(fp);

    unsigned char checksum[HASH_SIZE];
    compute_sha256(filedata, filesize, checksum);

    uLongf compressed_size = compressBound(filesize);
    unsigned char *compressed_data = malloc(compressed_size);
    if (!compressed_data) {
        fprintf(stderr, "Memory allocation error.\n");
        free(filedata);
        return -1;
    }
    if (compress(compressed_data, &compressed_size, filedata, filesize) != Z_OK) {
        fprintf(stderr, "Compression failed.\n");
        free(filedata);
        free(compressed_data);
        return -1;
    }
    free(filedata);

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "Failed to generate IV.\n");
        free(compressed_data);
        return -1;
    }
    int ciphertext_len = compressed_size + EVP_MAX_BLOCK_LENGTH;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation error.\n");
        free(compressed_data);
        return -1;
    }
    ciphertext_len = aes_encrypt(compressed_data, compressed_size, key, iv, ciphertext);
    free(compressed_data);

    // Записуємо метадані та зашифровані дані файлу до архіву
    unsigned short path_len = strlen(relative_path) + 1;
    fwrite(&path_len, sizeof(path_len), 1, archive_file);
    fwrite(relative_path, 1, path_len, archive_file);
    fwrite(iv, 1, IV_SIZE, archive_file);
    fwrite(&ciphertext_len, sizeof(int), 1, archive_file);
    fwrite(ciphertext, 1, ciphertext_len, archive_file);
    fwrite(checksum, 1, HASH_SIZE, archive_file);

    free(ciphertext);
    return 0;
}

/**
 * @brief Рекурсивно обробляє каталог і додає його вміст до архіву.
 * 
 * @param dirpath Шлях до каталогу.
 * @param base_path Базовий шлях для каталогу в архіві.
 * @param archive_file Вказівник на архівний файл.
 * @param key Ключ для шифрування файлів у каталозі.
 * @return int Повертає 0 при успіху, інше значення при помилці.
 */
static int process_directory(const char *dirpath, const char *base_path, FILE *archive_file, const unsigned char *key) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Failed to open directory %s\n", dirpath);
        return -1;
    }

    struct dirent *entry;
    char path_buffer[1024];
    char relative_path[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(path_buffer, sizeof(path_buffer), "%s%c%s", dirpath, PATH_SEPARATOR, entry->d_name);
        snprintf(relative_path, sizeof(relative_path), "%s%c%s", base_path, PATH_SEPARATOR, entry->d_name);

        struct stat path_stat;
        if (stat(path_buffer, &path_stat) != 0) {
            fprintf(stderr, "Failed to stat %s\n", path_buffer);
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            process_directory(path_buffer, relative_path, archive_file, key);
        } else if (S_ISREG(path_stat.st_mode)) {
            add_file(path_buffer, relative_path, archive_file, key);
        }
    }

    closedir(dir);
    return 0;
}

/**
 * @brief Витягує файли з архіву.
 * 
 * @param archive_path Шлях до архівного файлу.
 * @param extraction_path Директорія для збереження витягнутих файлів.
 * @param key 256-бітний ключ для розшифрування.
 * @return int Повертає 0 при успіху, інше значення при помилці.
 */
int extract_archive(const char *archive_path, const char *extraction_path, const unsigned char *key) {
    FILE *archive_file = fopen(archive_path, "rb");
    if (!archive_file) {
        fprintf(stderr, "Failed to open archive file %s\n", archive_path);
        return -1;
    }

    char header[8];
    fread(header, 1, 8, archive_file);
    if (memcmp(header, "CARCHIVE", 8) != 0) {
        fprintf(stderr, "Invalid archive file.\n");
        fclose(archive_file);
        return -1;
    }

    unsigned char archive_iv[IV_SIZE];
    fread(archive_iv, 1, IV_SIZE, archive_file);

    while (!feof(archive_file)) {
        unsigned short path_len;
        if (fread(&path_len, sizeof(path_len), 1, archive_file) != 1) {
            break;
        }

        char *relative_path = malloc(path_len);
        fread(relative_path, 1, path_len, archive_file);

        unsigned char file_iv[IV_SIZE];
        fread(file_iv, 1, IV_SIZE, archive_file);

        int ciphertext_len;
        fread(&ciphertext_len, sizeof(int), 1, archive_file);

        unsigned char *ciphertext = malloc(ciphertext_len);
        fread(ciphertext, 1, ciphertext_len, archive_file);

        unsigned char checksum[HASH_SIZE];
        fread(checksum, 1, HASH_SIZE, archive_file);

        unsigned char *plaintext = malloc(ciphertext_len);
        int plaintext_len = aes_decrypt(ciphertext, ciphertext_len, key, file_iv, plaintext);
        free(ciphertext);

        if (plaintext_len < 0) {
            fprintf(stderr, "Decryption failed for file %s\n", relative_path);
            free(relative_path);
            free(plaintext);
            fclose(archive_file);
            return -1;
        }

        uLongf decompressed_size = plaintext_len * 5;
        unsigned char *decompressed_data = malloc(decompressed_size);
        if (!decompressed_data) {
            fprintf(stderr, "Memory allocation error.\n");
            free(relative_path);
            free(plaintext);
            fclose(archive_file);
            return -1;
        }
        if (uncompress(decompressed_data, &decompressed_size, plaintext, plaintext_len) != Z_OK) {
            fprintf(stderr, "Decompression failed for file %s\n", relative_path);
            free(relative_path);
            free(plaintext);
            free(decompressed_data);
            fclose(archive_file);
            return -1;
        }
        free(plaintext);

        unsigned char calculated_checksum[HASH_SIZE];
        compute_sha256(decompressed_data, decompressed_size, calculated_checksum);
        if (memcmp(checksum, calculated_checksum, HASH_SIZE) != 0) {
            fprintf(stderr, "Checksum mismatch for file %s\n", relative_path);
            free(relative_path);
            free(decompressed_data);
            fclose(archive_file);
            return -1;
        }

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s%c%s", extraction_path ? extraction_path : ".", PATH_SEPARATOR, relative_path);

        char *last_sep = strrchr(full_path, PATH_SEPARATOR);
        if (last_sep) {
            *last_sep = '\0';
            mkdir(full_path);
            *last_sep = PATH_SEPARATOR;
        }

        FILE *output_file = fopen(full_path, "wb");
        if (!output_file) {
            fprintf(stderr, "Failed to create output file %s\n", full_path);
            free(relative_path);
            free(decompressed_data);
            fclose(archive_file);
            return -1;
        }
        fwrite(decompressed_data, 1, decompressed_size, output_file);
        fclose(output_file);

        free(relative_path);
        free(decompressed_data);
    }

    fclose(archive_file);

    if (remove(archive_path) != 0) {
        fprintf(stderr, "Failed to remove archive file %s\n", archive_path);
    } else {
        printf("Archive file %s has been successfully deleted.\n", archive_path);
    }

    return 0;
}

/**
 * @brief Отримує розмір файлу.
 * 
 * @param filename Шлях до файлу.
 * @return long Розмір файлу в байтах або -1 при помилці.
 */
long get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

/**
 * @brief Порівнює розмір архіву з розміром, створеним стандартним інструментом tar.
 * 
 * @param archive_path Шлях до архівного файлу.
 * @param input_paths Масив шляхів до файлів або каталогів.
 * @param input_count Кількість файлів або каталогів.
 */
void compare_with_standard_tools(const char *archive_path, const char **input_paths, size_t input_count) {
    char tar_command[1024];
    snprintf(tar_command, sizeof(tar_command), "tar -czf temp.tar.gz %s", input_paths[0]);
    system(tar_command);

    long archive_size = get_file_size(archive_path);
    long tar_size = get_file_size("temp.tar.gz");

    printf("\nSize comparison:\n");
    printf("Custom Archive Size: %ld bytes\n", archive_size);
    printf("TAR Archive Size: %ld bytes\n", tar_size);

    remove("temp.tar.gz");
}
