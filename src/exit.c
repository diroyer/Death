#include "syscall.h"

void end(void) {
	exit(0);
	__builtin_unreachable();
}
