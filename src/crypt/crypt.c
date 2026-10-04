#include "crypt.h"
#include "main.h"
#include "syscall.h"


uint8_t __attribute__((section(".text#"))) g_algo[ALGO_MAX] = {0};
uint16_t __attribute__((section(".text#"))) g_algo_ri = 0;

int8_t __attribute__((section(".text#"))) g_encrypt_type_target = -1;
int8_t __attribute__((section(".text#"))) g_encrypt_type_self = -1;

static inline uint8_t ft_nrand(void) {

	if (g_algo[0] == 0) {
		getrandom(g_algo, ALGO_MAX, 0);
	}

	uint8_t rand = g_algo[g_algo_ri];
	g_algo_ri = (g_algo_ri + 1 < ALGO_MAX) ? g_algo_ri + 1 : 0;
	return rand;
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

int crypt(data_t *data) {

	if (g_is_encrypted) {
		return 0;
	}

	crypt_params_t params;

	algo_t algo = ft_nrand() % ALGO_MAX;

	g_encrypt_type_target = algo;

	t_params_init_func init_func = get_params_init_func(algo);
	t_encrypt_func encrypt_func = get_encrypt_func(algo);

	crypt_params_init(&params, algo, data->file, data->size);

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
