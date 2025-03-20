#include "utils.h"
#include <string.h>
#include "syscall.h"

#ifdef DEBUG
void putnbr_impl(size_t n) {
	if (n > 9) {
		putnbr_impl(n / 10);
	}
	char c = n % 10 + '0';
	write(1, &c, 1);
}

void putnbr(size_t n) {
	putnbr_impl(n);
	write(1, "\n", 1);
}

void print_env(char **envp)
{
	write(1, envp[0], ft_strlen(envp[0]));
	for (int i = 0; envp[i] != NULL; i++) {
		write(1, envp[i], ft_strlen(envp[i]));
		write(1, STR("\n"), 1);
	}
}
#endif

int	ft_strlen(const char *s)
{
	int i = 0;
	while (s[i])
		i++;
	return (i);
}

int ft_strnlen(const char *s, size_t n) {
	size_t i = 0;
	while (*s && i < n) {
		i++;
		s++;
	}
	return (i);
}

void	*ft_memset(void *b, int c, size_t len) {
	uint8_t *ptr = b;
	for (size_t i = 0; i < len; i++) {
		ptr[i] = c;
	}
	return b;
}

void	*ft_memcpy(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
	return dst;
}

void	*ft_mempcpy(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
	return d + size;
}


void	ft_memmove(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	if (d < s) {
		for (size_t i = 0; i < size; i++) {
			d[i] = s[i];
		}
	} else {
		for (size_t i = size; i > 0; i--) {
			d[i - 1] = s[i - 1];
		}
	}
}

int	ft_memcmp(const void *s1, const void *s2, size_t size) {
	int delta;
	unsigned char *p1 = (unsigned char *)s1;
	unsigned char *p2 = (unsigned char *)s2;

	for (size_t i = 0; i < size; ++i) {
		delta = *(unsigned char *)p1 - *(unsigned char *)p2;
		if (delta != 0) {
			return delta;
		}
		p1++;
		p2++;
	}

	return 0;
}

void *ft_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }

    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (h[i] == n[0] && ft_memcmp(&h[i], n, needle_len) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

char *ft_strncpy(char *restrict dst, const char *restrict src, size_t sz)
{
	ft_stpncpy(dst, src, sz);
	return dst;
}

char *ft_stpncpy(char *restrict dst, const char *restrict src, size_t sz)
{
	ft_memset(dst, 0, sz);
	return ft_mempcpy(dst, src, ft_strnlen(src, sz));
}

int	ft_strcmp(const char *s1, const char *s2)
{
	while (*s1 && *s2 && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

//void *search_signature(t_data *data, const char *key) {
//	if (!data || !data->file || !key) {
//		return NULL;
//    }
//
//    size_t key_len = ft_strlen(key);
//    if (key_len == 0 || key_len > data->size) {
//		return NULL;
//    }
//
//    void *found = ft_memmem(data->file, data->size, key, key_len);
//    return found;
//}

/* old functions */
//
//char *ft_strncat(char *restrict dst, const char *restrict src, size_t sz)
//{
//	int   len;
//	char  *p;
//
//	len = ft_strnlen(src, sz);
//	p = dst + ft_strlen(dst);
//	p = ft_mempcpy(p, src, len);
//	*p = '\0';
//
//	return dst;
//}

//size_t ft_memindex(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
//    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
//        return 0;
//    }
//
//    const unsigned char *h = (const unsigned char *)haystack;
//    const unsigned char *n = (const unsigned char *)needle;
//
//    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
//        if (h[i] == n[0] && ft_memcmp(&h[i], n, needle_len) == 0) {
//			return i;
//        }
//    }
//    return 0;
//}

//size_t	ft_strncmp(const char *s1, const char *s2, size_t n) {
//	for (size_t i = 0; i < n; i++) {
//		if (s1[i] != s2[i])
//			return (s1[i] - s2[i]);
//		if (s1[i] == '\0')
//			return 0;
//	}
//	return 0;
//}

//void *ft_strnstr(const char *haystack, const char *needle, size_t len) {
//	size_t needle_len = ft_strlen(needle);
//	if (needle_len == 0)
//		return (char *)haystack;
//	for (size_t i = 0; i < len; i++) {
//		if (haystack[i] == needle[0]) {
//			if (ft_strncmp(haystack + i, needle, needle_len) == 0)
//				return (char *)haystack + i;
//		}
//	}
//	return NULL;
//}
