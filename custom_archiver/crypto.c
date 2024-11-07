// crypto.c

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

// Function to generate key from password using SHA-256
void generate_key_from_password(const char *password, unsigned char *key) {
    SHA256((const unsigned char *)password, strlen(password), key);
}

// Function to compute SHA-256 checksum
void compute_sha256(const unsigned char *data, size_t data_len, unsigned char *hash) {
    SHA256(data, data_len, hash);
}

// Function to encrypt data using AES-256-CBC
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Function to decrypt data using AES-256-CBC
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrypt ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
