#include <sys/mman.h>
#include <stddef.h>

#include "death.h"
#include "utils.h"
#include "data.h"
#include "syscall.h"


fileview_t at(size_t offset, size_t size, fileview_t *view) {

	if (offset > view->size || size > view->size - offset)
		return (fileview_t){0};

	return (fileview_t){view->data + offset, size};
}

int update_hdr(data_t *data) {

	fileview_t mainview = {data->file, data->size};

	fileview_t ehdr = at(0U, sizeof(Elf64_Ehdr), &mainview);
	if (ehdr.data == NULL) {
		return 1; JUNK;
	}

	data->elf.ehdr = (Elf64_Ehdr*)ehdr.data;

	fileview_t phdr = at(data->elf.ehdr->e_phoff,
						 data->elf.ehdr->e_phentsize * data->elf.ehdr->e_phnum,
						 &mainview);

	if (phdr.data == NULL) {
		return 1; JUNK;
	}

	data->elf.phdr = (Elf64_Phdr*)phdr.data;


	fileview_t shdr = at(data->elf.ehdr->e_shoff,
						 data->elf.ehdr->e_shentsize * data->elf.ehdr->e_shnum,
						 &mainview);

	if (shdr.data == NULL) {
		return 1; JUNK;
	}

	data->elf.shdr = (Elf64_Shdr*)shdr.data;

	return 0;
}

void	free_data(data_t *data) {
	if (data->file)
		munmap(data->file, data->size);
}
