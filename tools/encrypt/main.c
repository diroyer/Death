#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int decrypt(uint8_t *data, const size_t size, uint64_t key);

void encrypt(uint8_t *data, const size_t size, uint64_t key) {
	for (size_t i = 0; i < size; i++) {
		//data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
		uint8_t k = (key >> (8 * (i % 8))) & 0xFF;

		data[i] ^= k;
		data[i] += k;

		key = (key >> 7) | (key << (64 - 7));
		key ^= 0x9e3779b97f4a7c15;

	}
}

void decrypt_C(uint8_t *data, const size_t size, uint64_t key) {
	for (size_t i = 0; i < size; i++) {
		uint8_t k = (key >> (8 * (i % 8))) & 0xFF;

		data[i] -= k;
		data[i] ^= k;

		key = (key >> 7) | (key << (64 - 7));
		key ^= 0x9e3779b97f4a7c15;
	}
}

int main() {

	uint8_t data[29] = "Hello, World! This is a test!";
	uint64_t key = 0x1234567890ABCDEF;

	encrypt(data, sizeof(data) - 1, key);

	printf("Encrypted: %s\n", data);

	//if (decrypt(data, sizeof(data) - 1, key) == -1) {
	//	printf("Decryption failed!\n");
	//	return -1;
	//}
	//

	decrypt_C(data, sizeof(data) - 1, key);
	//encrypt(data, sizeof(data) - 1, key);

	printf("Decrypted: %s\n", data);
}
