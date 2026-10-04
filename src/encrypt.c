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

void decrypt(uint8_t *data, const size_t size, uint8_t *key) {
	for (size_t i = 0; i < size; i++) {
		//data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
		data[i] ^= key[i % KEY_SIZE];
	}
}

void xor_encrypt(const crypt_params_t *params) {
	const xor_params_t *xor_params = &params->params.xor_params;
	for (size_t i = 0; i < params->size; i++) {
		xor_params->key[i] ^= xor_params->key[i % KEY_SIZE];
	}
}

t_encrypt_func get_encrypt_func(algo_t algo) {
	switch (algo) {
		case XOR:
			return xor_encrypt;
		default:
			return NULL;
	}
}

