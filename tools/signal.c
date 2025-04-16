#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

//static void signal_handler(int sig)
//{
//	if (sig == SIGCHLD)
//		while (waitpid(-1, NULL, WNOHANG) > 0);
//	logger(STR("signal received\n"));
//}
//
//static int ft_sigemptyset(sigset_t *set)
//{
//	for (size_t i = 0; i < _SIGSET_NWORDS; i++) {
//		set->__val[i] = 0;
//	}
//	return 0;
//}
//void signal_init(void)
//{
//	struct sigaction sa = {
//		.sa_handler = signal_handler,
//		.sa_flags = SA_RESTART | SA_NOCLDSTOP
//	};
//
//	ft_sigemptyset(&sa.sa_mask);
//
//	_sigaction(SIGCHLD, &sa, NULL, 8);
//}

static inline long syscall_wrapper(long syscall_number, ...) {
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

	__asm__ volatile (
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

    return result;
}

#define syscall0(number) syscall_wrapper(number)
#define syscall1(number, arg1) syscall_wrapper(number, arg1)
#define syscall2(number, arg1, arg2) syscall_wrapper(number, arg1, arg2)
#define syscall3(number, arg1, arg2, arg3) syscall_wrapper(number, arg1, arg2, arg3)
#define syscall4(number, arg1, arg2, arg3, arg4) syscall_wrapper(number, arg1, arg2, arg3, arg4)
#define syscall5(number, arg1, arg2, arg3, arg4, arg5) syscall_wrapper(number, arg1, arg2, arg3, arg4, arg5)
#define syscall6(number, arg1, arg2, arg3, arg4, arg5, arg6) syscall_wrapper(number, arg1, arg2, arg3, arg4, arg5, arg6)

void signal_init() {
    struct sigaction act;
    
    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    
    //if (sigaction(SIGTERM, &act, NULL) == -1) {
    //    perror("sigaction");
    //}
    //
    // Alternative avec inline assembly en x86_64
	//sigemptyset(&act.sa_mask);
	//
	struct stat st;
	syscall_wrapper(SYS_write, 1, "Hello World!\n", 13);
	int fd = syscall_wrapper(SYS_open, "test.txt", O_RDWR);

	syscall_wrapper(SYS_fstat, fd, &st);

	void *file = (void *)syscall_wrapper(SYS_mmap, 0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	//print file
	syscall_wrapper(SYS_write, 1, file, st.st_size);

	syscall_wrapper(SYS_rt_sigaction, SIGTERM, &act, NULL, 8);
	syscall3(SYS_write, 1, "Hello World!\n", 13);

	
	//if (sigaction(SIGINT, &act, NULL) == -1) {
	//    perror("sigaction");
	//}
	//
	// Alternative avec inline assembly en x86_64
}

int main() {
    signal_init();
    return 0;
}
