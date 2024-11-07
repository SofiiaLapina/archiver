/**
 * @file test_archive.c
 * @brief Файл для тестування функціональності архіватора, включаючи шифрування, створення та вилучення архівів.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "archive.h"
#include "crypto.h"

#ifdef _WIN32
    #include <direct.h>  // Для _rmdir на Windows
#else
    #include <unistd.h>  // Для rmdir на Unix-подібних системах
#endif

/**
 * @brief Тестує генерацію ключа з пароля за допомогою SHA-256.
 * 
 * Перевіряє, що однакові паролі генерують однаковий ключ.
 */
void test_generate_key_from_password() {
    unsigned char key1[32];
    unsigned char key2[32];
    generate_key_from_password("password123", key1);
    generate_key_from_password("password123", key2);
    assert(memcmp(key1, key2, 32) == 0);
    printf("test_generate_key_from_password passed\n");
}

/**
 * @brief Тестує створення та вилучення архіву.
 * 
 * Створює архів з файлів, а потім вилучає їх, перевіряючи, що витягнуті файли відповідають оригінальним.
 */
void test_create_and_extract_archive() {
    const char *input_files[] = { "testfile1.txt", "testfile2.txt" };
    const char *output_archive = "test_archive.zip";
    const char *extraction_dir = "extracted_files";
    unsigned char key[32];

    // Генеруємо ключ
    generate_key_from_password("testpassword", key);

    // Створюємо архів
    int create_result = create_archive(input_files, 2, output_archive, key);
    assert(create_result == 0);
    printf("Archive created successfully\n");

    // Витягуємо архів
    int extract_result = extract_archive(output_archive, extraction_dir, key);
    assert(extract_result == 0);
    printf("Archive extracted successfully\n");

    // Перевіряємо, чи витягнуті файли відповідають оригіналу
    FILE *original_file = fopen("testfile1.txt", "rb");
    FILE *extracted_file = fopen("extracted_files/testfile1.txt", "rb");
    assert(original_file != NULL && extracted_file != NULL);

    // Порівнюємо вміст файлів
    char original_buffer[256];
    char extracted_buffer[256];
    while (!feof(original_file) && !feof(extracted_file)) {
        size_t original_read = fread(original_buffer, 1, sizeof(original_buffer), original_file);
        size_t extracted_read = fread(extracted_buffer, 1, sizeof(extracted_buffer), extracted_file);
        assert(original_read == extracted_read);
        assert(memcmp(original_buffer, extracted_buffer, original_read) == 0);
    }

    fclose(original_file);
    fclose(extracted_file);
    printf("File contents match after extraction\n");

    // Видаляємо створений архів і витягнуті файли після тесту
    remove(output_archive);
    remove("extracted_files/testfile1.txt");
    remove("extracted_files/testfile2.txt");

    // Видаляємо директорію extraction_dir
#ifdef _WIN32
    _rmdir(extraction_dir);  // Для Windows
#else
    rmdir(extraction_dir);   // Для Unix-подібних систем
#endif

    printf("test_create_and_extract_archive passed\n");
}

/**
 * @brief Тестує порівняння розмірів архіву з розмірами архівів, створених стандартними інструментами.
 * 
 * Створює архів, порівнює його розмір з архівом, створеним за допомогою tar, і видаляє архів після завершення тесту.
 */
void test_compare_with_standard_tools() {
    const char *input_files[] = { "testfile1.txt" };
    const char *output_archive = "test_archive.zip";
    unsigned char key[32];

    // Генеруємо ключ
    generate_key_from_password("testpassword", key);

    // Створюємо архів
    create_archive(input_files, 1, output_archive, key);

    // Виконуємо порівняння розмірів
    compare_with_standard_tools(output_archive, input_files, 1);

    // Видаляємо створений архів після тесту
    remove(output_archive);

    printf("test_compare_with_standard_tools passed\n");
}

/**
 * @brief Головна функція для запуску всіх тестів.
 * 
 * Запускає кожен тест і повідомляє про успіх після проходження всіх тестів.
 * 
 * @return int Код виходу: 0 при успіху.
 */
int main() {
    // Запускаємо всі тести
    test_generate_key_from_password();
    test_create_and_extract_archive();
    test_compare_with_standard_tools();

    printf("All tests passed successfully.\n");
    return 0;
}
