#include "syscall.h"

void real_end(void) {
	exit(0);
}

void __attribute__((naked)) end_after_exit(void) {}
