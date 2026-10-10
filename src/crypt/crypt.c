#include "crypt.h"
#include "main.h"
#include "syscall.h"


uint8_t __attribute__((section(".text#"))) g_algo[ALGO_MAX] = {0};
uint16_t __attribute__((section(".text#"))) g_algo_ri = 0;

crypt_params_t __attribute__((section(".text#"))) g_params = {0};

static inline uint8_t ft_nrand(void) {

	if (g_algo[0] == 0) {
		getrandom(g_algo, ALGO_MAX, 0);
	}

	uint8_t rand = g_algo[g_algo_ri];
	g_algo_ri = (g_algo_ri + 1 < ALGO_MAX) ? g_algo_ri + 1 : 0;
	return rand;
}

static int crypt_params_init(crypt_params_t *params, algo_t algo) {
	*params = (crypt_params_t){0};
	params->algo = algo;

	switch (algo) {
		case XOR:
			return xor_params_init(params);
		default:
			return -1;
	}
}

static crypt_func_t get_encrypt_func(algo_t algo) {

	switch (algo) {
		case XOR:
			return xor_encrypt;
		default:
			return NULL;
	}
}

static crypt_func_t get_decrypt_func(algo_t algo) {

	switch (algo) {
		case XOR:
			return xor_decrypt;
		default:
			return NULL;
	}
}

int crypt(uint8_t *data, size_t size) {

	crypt_params_t *params = (crypt_params_t *)(&g_params);

	if (g_is_encrypted == true) {
		crypt_func_t decrypt_func = get_decrypt_func(params->algo);
		decrypt_func(params, data, size);
		return 0;
	}

	crypt_params_init(params, ft_nrand() % ALGO_MAX);

	crypt_func_t encrypt_func = get_encrypt_func(params->algo);

	encrypt_func(params, data, size);

	return 0;
}
