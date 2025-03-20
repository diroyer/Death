#ifndef PESTILENCE_H
#define PESTILENCE_H

#include <sys/ptrace.h>
#include <stdint.h>
#include <sys/types.h>

#define DEFAULT_KEY /*0xdeadbeef*/ 0x9e3779b97f4a7c15

void encrypt(uint8_t *data, const size_t size, const uint64_t key);
int64_t gen_key_64(void);
int pestilence(void);
#endif
