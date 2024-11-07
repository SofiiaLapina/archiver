/**
 * @file crypto.h
 * @brief Заголовний файл для функцій шифрування, розшифрування, генерації хешів та порівняння розмірів архівів.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

/**
 * @brief Генерує ключ із пароля за допомогою SHA-256.
 * 
 * @param password Вказівник на пароль, з якого буде згенеровано ключ.
 * @param key Буфер для збереження згенерованого 256-бітного ключа.
 */
void generate_key_from_password(const char *password, unsigned char *key);

/**
 * @brief Обчислює контрольну суму SHA-256 для даних.
 * 
 * @param data Вказівник на дані, для яких потрібно обчислити контрольну суму.
 * @param data_len Довжина даних у байтах.
 * @param hash Буфер для збереження обчисленої SHA-256 хеш суми (32 байти).
 */
void compute_sha256(const unsigned char *data, size_t data_len, unsigned char *hash);

/**
 * @brief Шифрує дані за допомогою AES-256-CBC.
 * 
 * @param plaintext Вказівник на відкритий текст для шифрування.
 * @param plaintext_len Довжина відкритого тексту у байтах.
 * @param key Вказівник на 256-бітний ключ для шифрування.
 * @param iv Вказівник на вектор ініціалізації (IV) розміром 16 байтів.
 * @param ciphertext Буфер для збереження зашифрованого тексту.
 * @return int Довжина зашифрованого тексту при успіху, -1 при помилці.
 */
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

/**
 * @brief Розшифровує дані за допомогою AES-256-CBC.
 * 
 * @param ciphertext Вказівник на зашифрований текст.
 * @param ciphertext_len Довжина зашифрованого тексту у байтах.
 * @param key Вказівник на 256-бітний ключ для розшифрування.
 * @param iv Вказівник на вектор ініціалізації (IV) розміром 16 байтів.
 * @param plaintext Буфер для збереження розшифрованого тексту.
 * @return int Довжина розшифрованого тексту при успіху, -1 при помилці.
 */
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

/**
 * @brief Порівнює розміри архівів, створених з використанням поточного архіватора та стандартних інструментів (zip і tar).
 * 
 * @param archive_path Шлях до архіву, створеного поточним архіватором.
 * @param input_paths Масив шляхів до файлів або каталогів для архівування.
 * @param input_count Кількість файлів або каталогів у масиві input_paths.
 */
void compare_with_standard_tools(const char *archive_path, const char **input_paths, size_t input_count);

#endif // CRYPTO_H
