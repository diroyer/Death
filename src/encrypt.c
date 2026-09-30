#include "data.h"
#include "encrypt.h"

void encrypt(uint8_t *data, const size_t size, uint8_t *key) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= key[i % KEY_SIZE];
	}
}

void encrypt_offset(uint8_t *data, const size_t size, uint8_t *key, size_t offset) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= key[(i + offset) % KEY_SIZE];
	}
}

void decrypt(uint8_t *data, const size_t size, int64_t key) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
	}
}
