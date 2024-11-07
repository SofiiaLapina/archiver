/**
 * @file crypto.c
 * @brief Реалізація функцій для шифрування, розшифрування та генерації хешів.
 */

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

/**
 * @brief Генерує ключ із пароля за допомогою SHA-256.
 * 
 * @param password Вказівник на пароль, з якого буде згенеровано ключ.
 * @param key Буфер для збереження згенерованого 256-бітного ключа.
 */
void generate_key_from_password(const char *password, unsigned char *key) {
    SHA256((const unsigned char *)password, strlen(password), key);
}

/**
 * @brief Обчислює контрольну суму SHA-256 для даних.
 * 
 * @param data Вказівник на дані, для яких потрібно обчислити контрольну суму.
 * @param data_len Довжина даних у байтах.
 * @param hash Буфер для збереження обчисленої SHA-256 хеш суми (32 байти).
 */
void compute_sha256(const unsigned char *data, size_t data_len, unsigned char *hash) {
    SHA256(data, data_len, hash);
}

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
                unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Створення та ініціалізація контексту
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Ініціалізація операції шифрування
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Шифрування відкритого тексту
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Завершення шифрування
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Очищення контексту
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

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
                unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Створення та ініціалізація контексту
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Ініціалізація операції розшифрування
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Розшифрування зашифрованого тексту
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Завершення розшифрування
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Очищення контексту
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
