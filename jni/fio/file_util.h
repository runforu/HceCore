
#ifndef FILE_UTIL_H
#define FILE_UTIL_H

int fio_write(const char* file_path, const char* buffer, unsigned int size);

int fio_read(const char* file_path, char* buffer, unsigned int max_size);

#endif
