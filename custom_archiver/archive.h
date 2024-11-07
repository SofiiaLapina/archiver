/**
 * @file archive.h
 * @brief Заголовний файл для функцій архівування та вилучення архівів.
 */

#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stddef.h>

/**
 * @brief Створює архів з файлів або каталогів.
 * 
 * @param input_paths Масив шляхів до файлів або каталогів для архівування.
 * @param input_count Кількість файлів або каталогів у масиві input_paths.
 * @param output_path Шлях до створюваного архівного файлу.
 * @param key Ключ шифрування для архіву (256-бітний).
 * @return int Повертає 0 при успішному створенні архіву, інше значення при помилці.
 */
int create_archive(const char **input_paths, size_t input_count, const char *output_path, const unsigned char *key);

/**
 * @brief Вилучає файли з архіву.
 * 
 * @param archive_path Шлях до архівного файлу.
 * @param extraction_path Шлях до директорії для збереження вилучених файлів.
 * @param key Ключ шифрування для розархівації (256-бітний).
 * @return int Повертає 0 при успішному вилученні архіву, інше значення при помилці.
 */
int extract_archive(const char *archive_path, const char *extraction_path, const unsigned char *key);

#endif // ARCHIVE_H
