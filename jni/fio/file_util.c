#include <stdio.h>

int fio_write(const char* file_path, const char* buffer, unsigned int size) {
    if (file_path == NULL || buffer == NULL || size < 1) {
        return -1;
    }
    FILE * file;
    file = fopen(file_path, "wb");
    if (file == NULL) {
        return -1;
    }
    int count = fwrite(buffer, 1, size, file);
    fclose(file);
    return count;
}

int fio_read(const char* file_path, char* buffer, unsigned int max_size) {
    if (file_path == NULL || buffer == NULL || max_size < 1) {
        return -1;
    }
    FILE * file;
    file = fopen(file_path, "rb");
    if (file == NULL) {
        return -1;
    }
    int count = fread(buffer, 1, max_size, file);
    fclose(file);
    return count;
}
