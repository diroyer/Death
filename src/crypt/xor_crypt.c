#include "data.h"
#include "main.h"
#include "crypt.h"
#include "syscall.h"

void xor_params_init(crypt_params_t *params) {
	params->algo = XOR;
	if (getrandom(params->params.xor_params.key, KEY_SIZE, 0) != KEY_SIZE) {
		params->error = 1;
	}
}

void xor_encrypt(const crypt_params_t *params) {
	const xor_params_t *xor_params = &params->params.xor_params;
	for (size_t i = 0; i < params->data.src_size; i++) {
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

void encrypt(uint8_t *data, const size_t size, uint8_t *key) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= key[i % KEY_SIZE];
	}
}

void decrypt(uint8_t *data, const size_t size, uint8_t *key) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= key[i % KEY_SIZE];
	}
}
