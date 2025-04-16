#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325
#define FNV_PRIME_64 0x00000100000001b3

uint64_t fnv1a_hash_64(const char *data, size_t len) {
    uint64_t hash = FNV_OFFSET_BASIS_64;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)data[i];
        hash *= FNV_PRIME_64;
    }
    return hash;
}

void hash_to_printable(uint64_t hash, char *output) {
    for (int i = 0; i < 8; i++) {
        output[i] = (hash % 95) + 32;
        hash /= 95;
    }
    output[8] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target> <self>\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *self = argv[2];

    uint64_t target_hash = fnv1a_hash_64(target, strlen(target));
    uint64_t self_hash = fnv1a_hash_64(self, strlen(self));
    
    uint64_t combined_hash = target_hash ^ self_hash;
    
    char fingerprint[9]; // 8 chars + null terminator
    hash_to_printable(combined_hash, fingerprint);

    printf("Fingerprint: %s\n", fingerprint);
    return 0;
}

