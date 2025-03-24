#ifndef MAP_H
# define MAP_H

# include <stdint.h>
# include <sys/types.h>
#include "data.h"

//uint8_t	*map_file(const char *filename, size_t *size);
int		map_file(const char *filename, data_t *data);
//uint8_t	*expand_file(uint8_t *file, size_t size, size_t new_size, data_t *data);

#endif
