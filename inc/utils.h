#ifndef UTILS_H
# define UTILS_H

# include <stdint.h>
# include <sys/types.h>

# include "data.h"

/* print */
void	putnbr(size_t n);

/* len */
int		ft_strlen(const char *s);
int		ft_strnlen(const char *s, size_t n);

/* mem functions */
void	ft_memmove(void *dst, const void *src, size_t size);
int		ft_memcmp(const void *s1, const void *s2, size_t size);
void	*ft_memset(void *b, int c, size_t len);
void	*ft_memcpy(void *dst, const void *src, size_t size);
void	*ft_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);
void	*ft_mempcpy(void *dst, const void *src, size_t size);

/* str functions */
char *ft_stpncpy(char *dst, const char *src, size_t sz);
char *ft_strncat(char *dst, const char *src, size_t sz);
char *ft_strncpy(char *dst, const char *src, size_t sz);
int	ft_strcmp(const char *s1, const char *s2);

/* rest of the functions */
void	*search_signature(t_data *data, const char *key);

#endif
