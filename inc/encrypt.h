#ifndef ENCRYPT_H
#define ENCRYPT_H

//#include "data.h"

#include <stdint.h>
#include <stddef.h>

void	encrypt(uint8_t *data, const size_t size, uint8_t *key);
void	decrypt(uint8_t *data, const size_t size, int64_t key);
void	encrypt_offset(uint8_t *data, const size_t size, uint8_t *key, size_t offset);

#endif
