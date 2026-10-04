#include "data.h"
#include "encrypt.h"
#include "syscall.h"

uint8_t __attribute__((section(".text#"))) g_algo[ALGO_MAX] = {0};
uint16_t __attribute__((section(".text#"))) g_algo_ri = 0;

static inline uint8_t ft_nrand(void) {

	if (g_algo[0] == 0) {
		getrandom(g_algo, ALGO_MAX, 0);
	}

	uint8_t rand = g_algo[g_algo_ri];
	g_algo_ri = (g_algo_ri + 1 < ALGO_MAX) ? g_algo_ri + 1 : 0;
	return rand;
}


static void xor_params_init(crypt_params_t *params) {
	params->algo = XOR;
	if (getrandom(params->params.xor_params.key, KEY_SIZE, 0) != KEY_SIZE) {
		params->error = 1;
	}
}

static void xor_encrypt(const crypt_params_t *params) {
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

static t_params_init_func get_params_init_func(algo_t algo) {

	switch (algo) {
		case XOR:
			return xor_params_init;
		default:
			return NULL;
	}
}

static void crypt_params_init(crypt_params_t *params, algo_t algo, uint8_t *data, size_t size) {
	params->algo = algo;
	params->data.src = data;
	params->data.src_size = size;
	params->error = 0;

	*params = (crypt_params_t){0};
	params->algo = algo;
	params->data.src = data;
	params->data.src_size = size;

	params->data.dst = data;
	params->data.dst_size = size;
}

static int main_encrypt(data_t *data) {

	(void)data;

	crypt_params_t params;

	algo_t algo = ft_nrand() % ALGO_MAX;

	t_params_init_func init_func = get_params_init_func(algo);
	t_encrypt_func encrypt_func = get_encrypt_func(algo);

	//crypt_params_init(&params, algo, algo_vars->data, algo_vars->size);

	if (init_func) {
		init_func(&params);
	}

	if (encrypt_func) {
		encrypt_func(&params);
	}

	if (params.error) {
		return -1;
	}

	return 0;
}

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
