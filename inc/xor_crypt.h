#ifndef XOR_CRYPT_H
#define XOR_CRYPT_H

#include <stdint.h>
#include <stddef.h>

/* forward declaration of the crypt_params_t structure */
typedef struct crypt_params_s crypt_params_t;

void	encrypt(uint8_t *data, const size_t size, uint8_t *key);
void	decrypt(uint8_t *data, const size_t size, uint8_t *key);

void	xor_params_init(crypt_params_t *params);

#endif
