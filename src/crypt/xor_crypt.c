#include "data.h"
#include "crypt.h"
#include "syscall.h"

int xor_params_init(crypt_params_t *params) {
	if (getrandom(params->xor_params.key, KEY_SIZE, 0) != KEY_SIZE) {
		return -1;
	}
	return 0;
}

void xor_encrypt(crypt_params_t *params, uint8_t *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= params->xor_params.key[i % KEY_SIZE];
	}
}

void xor_decrypt(crypt_params_t *params, uint8_t *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		data[i] ^= params->xor_params.key[i % KEY_SIZE];
	}
}
