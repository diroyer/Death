#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define DEFAULT_KEY /*0xdeadbeef*/ 0x9e3779b97f4a7c15




void encrypt_signature(char *signature, uint64_t hash) {
    size_t len = strlen(signature);
    for (size_t i = 0; i < len; i++) {
        signature[i] ^= (hash >> (8 * (i % 8))) & 0xFF;  // XOR avec chaque byte du hash
    }
}

int	ft_strlen(char *str)
{
	int i = 0;
	while (str[i])
		i++;
	return (i);
}

int main() {
    uint64_t hash = 0x9e3779b97f4a7c15;  // Clé par défaut
	//char signature[26] = "\x53\x1d\x27\x16\xd7\x1c\x17\xb6\x76\x55\x25\x1b\xdc\x1d\x17\xfc\x6c\x5c\x2e\x07\xcb\x01\x55\xe6\x7e\x00";
	char signature[] = "Death (c)oded by [diroyer]";

	printf("Taille de la signature : %d\n", ft_strlen(signature));


    printf("Avant chiffrement : %s\n", signature);
    encrypt_signature(signature, DEFAULT_KEY);
    printf("Après chiffrement : ");
    for (size_t i = 0; i < sizeof(signature) ; i++) {
        printf("\\x%02x", (unsigned char)signature[i]); // Affiche en hex
    }
    printf("\n");

    return 0;
}

