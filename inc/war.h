#ifndef WAR_H
# define WAR_H

# include <stdint.h>
# include <stddef.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <fcntl.h>
# include <limits.h>

# include "data.h"

//int self_name(data_t *data);
//int self_name(char *self_name);
//int self_fingerprint(data_t *data);
int war(size_t increment, file_t *file);
void update_fingerprint(char *fingerprint, data_t *data);

#endif
