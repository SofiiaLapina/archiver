/**
 * @file main.c
 * @brief Головний файл для роботи з архіватором: створення та вилучення архівів із шифруванням.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "archive.h"
#include "crypto.h"

/**
 * @brief Головна функція для запуску програми архіватора.
 * 
 * Використання:
 * - Створення архіву:
 *   ./archive_tool -c "path\\to\\archive\\name.zip" "path\\to\\archive\\contents" -p <password> | -g <key>
 * - Вилучення архіву:
 *   ./archive_tool -x "path\\to\\archive\\name.zip" "path\\to\\the\\place\\where\\to\\extract\\the\\archive" -p <password> | -g <key>
 * 
 * @param argc Кількість аргументів командного рядка.
 * @param argv Масив аргументів командного рядка.
 * @return int Код виходу: 0 при успіху, 1 при помилці.
 */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usages:\n");
        fprintf(stderr, "For creating archive:\n");
        fprintf(stderr, "  %s -c \"path\\to\\archive\\name.zip\" \"path\\to\\archive\\contents\" -p <password> | -g <key>\n", argv[0]);
        fprintf(stderr, "For extracting archive:\n");
        fprintf(stderr, "  %s -x \"path\\to\\archive\\name.zip\" \"path\\to\\the\\place\\where\\to\\extract\\the\\archive\" -p <password> | -g <key>\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    unsigned char key[32]; ///< 256-бітний ключ
    int key_provided = 0;
    int i = 2;
    const char *output_archive = NULL;
    const char *extraction_path = NULL;
    const char **input_paths = NULL;
    size_t input_count = 0;

    // Обробка прапорів -p та -g
    while (i < argc) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            char *password = argv[++i];
            generate_key_from_password(password, key);
            key_provided = 1;
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            char *key_input = argv[++i];
            if (strlen(key_input) != 32) {
                fprintf(stderr, "Error: Key must be exactly 32 characters (256 bits) long.\n");
                return 1;
            }
            memcpy(key, key_input, 32);
            key_provided = 1;
        } else if (strcmp(argv[1], "-c") == 0) {  // Режим створення архіву
            if (output_archive == NULL) {
                output_archive = argv[i];  // Ім'я вихідного архіву
            } else {
                input_paths = (const char **)realloc(input_paths, (input_count + 1) * sizeof(char *));
                input_paths[input_count++] = argv[i];  // Додаємо шлях до файлу/каталогу
            }
        } else if (strcmp(argv[1], "-x") == 0) {  // Режим вилучення архіву
            if (output_archive == NULL) {
                output_archive = argv[i];  // Файл архіву
            } else if (extraction_path == NULL) {
                extraction_path = argv[i];  // Шлях для вилучення
            }
        }
        i++;
    }

    // Якщо пароль або ключ не надано, запитуємо пароль
    if (!key_provided) {
        char password[256];
        printf("Enter password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0; // Видаляємо символ нового рядка
        generate_key_from_password(password, key);
    }

    if (strcmp(mode, "-c") == 0) {
        if (output_archive == NULL || input_count == 0) {
            fprintf(stderr, "Error: Insufficient arguments for creating an archive.\n");
            return 1;
        }

        // Створення архіву
        if (create_archive(input_paths, input_count, output_archive, key) != 0) {
            fprintf(stderr, "Failed to create archive.\n");
            return 1;
        }

        printf("Archive created successfully: %s\n", output_archive);

        // Порівняння розміру архіву зі стандартними інструментами (tar)
        compare_with_standard_tools(output_archive, input_paths, input_count);

    } else if (strcmp(mode, "-x") == 0) {
        if (output_archive == NULL || extraction_path == NULL) {
            fprintf(stderr, "Error: Insufficient arguments for extracting an archive.\n");
            return 1;
        }

        // Вилучення архіву
        if (extract_archive(output_archive, extraction_path, key) != 0) {
            fprintf(stderr, "Failed to extract archive.\n");
            return 1;
        }

        printf("Archive extracted successfully to %s\n", extraction_path);

    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        fprintf(stderr, "Use -c to create or -x to extract.\n");
        return 1;
    }

    return 0;
}
