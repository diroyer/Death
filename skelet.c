#include <unistd.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>

#define __asm__ __asm__ volatile

#define PUSH "push %rax\n"
#define POP "pop %rax\n"
#define NOP "nop\n"

#define PUSH_OP 0x50
#define POP_OP 0x58
#define NOP_OP 0x90

#define OP_64 0x48

#define RAX_OP 0x58

#define ADD 0x83

const uint8_t opcode[] = {0x83, 0x0};

#define JUNK __asm__(PUSH NOP NOP NOP NOP POP)
#define JUNK_LEN 6

static int abs_path(char *self_name) {
	char buf[PATH_MAX];
	char proc_self_exe[] = "/proc/self/exe";

	int ret = readlink(proc_self_exe, buf, PATH_MAX);
	if (ret == -1) {
		strncpy(self_name, "dummy", PATH_MAX);
		return -1;
	}
	buf[ret] = '\0';

	strncpy(self_name, buf, PATH_MAX);

	return 0;
}

static int check(uint8_t *self, size_t offset) {
	return (self[offset] == PUSH_OP &&
			self[offset + 1] == NOP_OP &&
			self[offset + 2] == NOP_OP &&
			self[offset + 3] == NOP_OP &&
			self[offset + 4] == NOP_OP &&
			self[offset + 5] == POP_OP);
}

static void replace_nop(uint8_t *self, size_t size) {
	for (size_t i = 0; i < size - JUNK_LEN; i++) {
		if (check(self, i)) {
			self[i + 1] = OP_64;
			self[i + 2] = ADD;
			self[i + 3] = 0xC0; // ModR/M byte
			self[i + 4] = 0x01;
			i += JUNK_LEN;
		}
	}
}

int main(void) {

	char self_name[PATH_MAX];

	JUNK;

	if (abs_path(self_name) == -1) {
		return -1;
	}

	JUNK;

	struct stat st;
	/* we could open the file with O_RDWR but text file is busy */

	int fd = open(self_name, O_RDONLY); JUNK;



	if (fd == -1) {
		return -1;
	}

	JUNK;

	if (fstat(fd, &st) == -1) {
		close(fd);
		return -1;
	}

	JUNK;



	/* we could use MAP_SHARED but we can't open the file with O_RDWR */
	uint8_t *self = (uint8_t *)mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (self == MAP_FAILED) {
		close(fd);
		return -1;
	}

	close(fd);

	replace_nop(self, st.st_size);

	if (unlink(self_name) == -1) {
		munmap(self, st.st_size);
		return -1;
	}

	fd = open(self_name, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);
	if (fd == -1)
		return -1;

	if (write(fd, self, st.st_size) == -1) {
		close(fd);
		munmap(self, st.st_size);
		return -1;
	}

	if (munmap(self, st.st_size) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}


