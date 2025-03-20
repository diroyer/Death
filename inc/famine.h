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

#endif
