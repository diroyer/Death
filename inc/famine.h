#ifndef FAMINE_H
# define FAMINE_H

#include <stddef.h>
#include <stdint.h>
#include "data.h"
#include "main.h"

typedef struct saved_vars_s {
	int start_offset;
	bool is_encrypted;
	uint8_t key[KEY_SIZE];
} saved_vars_t;


#endif
