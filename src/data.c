#include <sys/mman.h>
#include <stddef.h>

#include "death.h"
#include "utils.h"
#include "data.h"
#include "syscall.h"


t_fileview at(size_t offset, size_t size, t_fileview *view) {

	if (offset > view->size || size > view->size - offset)
		return (t_fileview){0};

	return (t_fileview){view->data + offset, size};

}

int update_hdr(t_data *data) {

	t_fileview mainview = {data->file, data->size};

	t_fileview ehdr = at(0U, sizeof(Elf64_Ehdr), &mainview);
	if (ehdr.data == NULL)
		return 1;

	//_printf("Debug: %p\n", ehdr.data);

	JUNK;

	data->elf.ehdr = (Elf64_Ehdr*)ehdr.data;

	t_fileview phdr = at(data->elf.ehdr->e_phoff,
						 data->elf.ehdr->e_phentsize * data->elf.ehdr->e_phnum,
						 &mainview);

	if (phdr.data == NULL)
		return 1;

	JUNK;

	data->elf.phdr = (Elf64_Phdr*)phdr.data;


	t_fileview shdr = at(data->elf.ehdr->e_shoff,
						 data->elf.ehdr->e_shentsize * data->elf.ehdr->e_shnum,
						 &mainview);

	if (shdr.data == NULL)
		return 1;

	JUNK;

	data->elf.shdr = (Elf64_Shdr*)shdr.data;

	return 0;
}


void	free_data(t_data *data) {
	if (data->file)
		munmap(data->file, data->size);
}
