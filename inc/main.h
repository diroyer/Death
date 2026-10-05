#ifndef MAIN_H
#define MAIN_H

#include <stdbool.h>
#include <stdint.h>

#define SIGNATURE_SIZE 44
#define MAGIC_NUMBER 0x0000ADDE
#define KEY_SIZE 2048
#define ORIG_TEXT_OFF 0x1337


#define VIRUS_SIZE (uintptr_t)&real_end - (uintptr_t)&_start
#define PAYLOAD_SIZE (uintptr_t)&real_end - (uintptr_t)&real_start
#define PACKER_SIZE (uintptr_t)&real_start - (uintptr_t)&_start


extern char	    g_signature[SIGNATURE_SIZE];
extern uint8_t	g_key[KEY_SIZE];
extern int	    g_start_offset;
extern char	    **g_envp;
extern bool	    g_is_self_decrypted;


extern void	real_end(void);
extern void	real_start(void);

#endif
