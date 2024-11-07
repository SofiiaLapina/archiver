// archive.h

#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stddef.h>

// Function to create an archive from files/directories
int create_archive(const char **input_paths, size_t input_count, const char *output_path, const unsigned char *key);

// Function to extract an archive
int extract_archive(const char *archive_path, const char *extraction_path, const unsigned char *key);

#endif // ARCHIVE_H
