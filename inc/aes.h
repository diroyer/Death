#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE 16 // 128 bits
#define AES_BLOCK_SIZE 16 // 128 bits
#define AES_ROUNDS 10
#define AES_NONCE_SIZE 12 // 96 bits
#define AES_EXPANDED_KEY_SIZE 176 // 11 * 16 bytes for AES-128
#define AES_COUNTER_SIZE 4 // 32 bits
#define AES_MAX_BLOCKS UINT32_MAX

typedef struct crypt_params_s crypt_params_t;

typedef struct
aes_params_s
{
	uint8_t	key[AES_KEY_SIZE];
	uint8_t	nonce[AES_NONCE_SIZE];
} aes_params_t;

void aes_encrypt(crypt_params_t *params, uint8_t *input, size_t size);
int aes_params_init(crypt_params_t *params);

#endif // AES_H
