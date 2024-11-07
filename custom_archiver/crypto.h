// crypto.h

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

// Function to generate key from password using SHA-256
void generate_key_from_password(const char *password, unsigned char *key);

// Function to compute SHA-256 checksum
void compute_sha256(const unsigned char *data, size_t data_len, unsigned char *hash);

// Function to encrypt data using AES-256-CBC
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

// Function to decrypt data using AES-256-CBC
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

// Function to compare archive sizes with standard tools (zip and tar)
void compare_with_standard_tools(const char *archive_path, const char **input_paths, size_t input_count);


#endif // CRYPTO_H
