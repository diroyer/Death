#ifndef CRYPT_H
#define CRYPT_H


#include <stdint.h>
#include <stddef.h>

#include "xor_crypt.h"
#include "aes.h"
#include "data.h"
#include "main.h"


extern bool g_is_encrypted;
extern crypt_params_t g_params;

int crypt(uint8_t *data, size_t size);

typedef enum algo_e
{
	XOR,
	AES_CTR,
	ALGO_MAX
}	algo_t;

typedef struct //__attribute__((packed))
crypt_params_s
{
	algo_t	algo;

	union
	{
		xor_params_t	xor_params;
		aes_params_t	aes_params;
	};

}	crypt_params_t;

typedef void (*crypt_func_t)(
	crypt_params_t *params,
	uint8_t *data,
	size_t size
);

typedef void (*params_init_func_t)(crypt_params_t *params);

#endif
