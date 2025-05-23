
int __attribute__((section(".text#"))) g_errno = 0;

extern inline long _syscall(long syscall_number, ...) {
	__builtin_va_list args;
	long result;

	long arg1, arg2, arg3, arg4, arg5, arg6;

	__builtin_va_start(args, syscall_number);
	arg1 = __builtin_va_arg(args, long);
	arg2 = __builtin_va_arg(args, long);
	arg3 = __builtin_va_arg(args, long);
	arg4 = __builtin_va_arg(args, long);
	arg5 = __builtin_va_arg(args, long);
	arg6 = __builtin_va_arg(args, long);
	__builtin_va_end(args);

	__asm__ __volatile__ (
			"movq %1, %%rax	\n\t"
			"movq %2, %%rdi	\n\t"
			"movq %3, %%rsi	\n\t"
			"movq %4, %%rdx	\n\t"
			"movq %5, %%r10	\n\t"  
			"movq %6, %%r8	\n\t"  
			"movq %7, %%r9	\n\t" 
			"syscall		\n\t"     
			"movq %%rax, %0	\n\t"
			: "=r" (result)
			: "r" (syscall_number), "r" (arg1), "r" (arg2), "r" (arg3),
			"r" (arg4), "r" (arg5), "r" (arg6)
			: "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"
		);

	if (result < 0) {
		g_errno = -result;
		return -1;
	}

    return result;
}
