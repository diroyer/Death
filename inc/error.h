#ifdef DEBUG
 #ifndef ERROR_H
 #define ERROR_H

 #define ERR_LEN 64
 #define ERRNO_COUNT 134

extern const char g_errno_str[ERRNO_COUNT][ERR_LEN];

const char *strerror(int err);

 #endif
#endif
