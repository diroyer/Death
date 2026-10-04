#ifndef ENCRYPT_H
#define ENCRYPT_H

//#include "data.h"

#include <stdint.h>
#include <stddef.h>

void	encrypt(uint8_t *data, const size_t size, uint8_t *key);
void	decrypt(uint8_t *data, const size_t size, uint8_t *key);
void	encrypt_offset(uint8_t *data, const size_t size, uint8_t *key, size_t offset);

typedef enum algo_e
{
	XOR,
}	algo_t;

typedef struct xor_params_s
{
	uint8_t	*key;
}	xor_params_t;

typedef struct crypt_params_s
{
	algo_t	algo;
	uint8_t	*dst;
	const uint8_t	*src;
	size_t	size;
	union
	{
		xor_params_t	xor_params;
	}	params;
}	crypt_params_t;

typedef void (*t_encrypt_func)(
	const crypt_params_t *params
);

t_encrypt_func	get_encrypt_func(algo_t algo);

#endif
