/* Text segment implementation */

#include "data.h"
#include "elf.h"
#include "text.h"

int	text(t_data *data, size_t payload_size) {

	Elf64_Ehdr	*ehdr	= data->elf.ehdr;
	Elf64_Phdr	*phdr	= data->elf.phdr;
	Elf64_Shdr	*shdr	= data->elf.shdr;

	for (size_t i = 0; i < ehdr->e_phnum; ++i) {

		if (phdr[i].p_type != PT_LOAD || (phdr[i].p_flags & PF_X) == 0)
			continue;

		data->packer.offset = phdr[i].p_offset + phdr[i].p_filesz;
		data->packer.addr = phdr[i].p_vaddr + phdr[i].p_filesz;
		uint64_t next_offset = phdr[i].p_offset + (phdr[i].p_memsz / PAGE_SIZE + 1) * PAGE_SIZE;
		uint64_t cave_size = next_offset - data->packer.offset;

		if (payload_size > cave_size)
			return 1;

		data->packer.old_entry = ehdr->e_entry;
		ehdr->e_entry     = phdr[i].p_vaddr + phdr[i].p_filesz;
		//phdr[i].p_flags  |= PF_W;
		phdr[i].p_filesz += payload_size;
		phdr[i].p_memsz  += payload_size;

		break;

	}

	for (size_t i = 0; i < ehdr->e_shnum; ++i) {

		if (shdr[i].sh_addr + shdr[i].sh_size == data->packer.addr) {
			shdr[i].sh_size += payload_size;
		}

	}

	return 0;
}
