#ifndef CRYPT_H
#define CRYPT_H

#include "xor_crypt.h"

#include "data.h"

#include <stdint.h>
#include <stddef.h>

extern bool g_is_encrypted;

int crypt(data_t *data);

typedef enum algo_e
{
	XOR,
	ALGO_MAX
}	algo_t;

typedef struct xor_params_s
{
	uint8_t	*key;
}	xor_params_t;

typedef struct crypt_data_s
{
	uint8_t	*dst;
	size_t	dst_size;

	const uint8_t	*src;
	size_t	src_size;
} crypt_data_t;

typedef struct crypt_params_s
{
	algo_t	algo;
	crypt_data_t	data;

	union
	{
		xor_params_t	xor_params;
	}	params;

	int error;
}	crypt_params_t;

typedef void (*t_encrypt_func)(
	const crypt_params_t *params
);

t_encrypt_func	get_encrypt_func(algo_t algo);
typedef void (*t_params_init_func)(crypt_params_t *params);

#endif
