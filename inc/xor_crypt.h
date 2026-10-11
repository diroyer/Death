#ifndef XOR_CRYPT_H
#define XOR_CRYPT_H

#include <stdint.h>
#include <stddef.h>

#define KEY_SIZE 2048


typedef struct //__attribute__((packed))
xor_params_s
{
	uint8_t	key[KEY_SIZE];
}	xor_params_t;

/* forward declaration of the crypt_params_t structure */
typedef struct crypt_params_s crypt_params_t;

void	encrypt(uint8_t *data, const size_t size, uint8_t *key);
void	decrypt(uint8_t *data, const size_t size, uint8_t *key);

int	xor_params_init(crypt_params_t *params);
//void	xor_encrypt(crypt_params_t *params);
//void	xor_decrypt(crypt_params_t *params);
void	xor_encrypt(crypt_params_t *params, uint8_t *data, size_t size);
void	xor_decrypt(crypt_params_t *params, uint8_t *data, size_t size);

#endif
