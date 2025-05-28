#include <limits.h>

#include "utils.h"
#include "signale.h"

//#define ft_sigmask(sig) (1UL << ((sig) - 1) % ULONG_WIDTH)
unsigned long int ft_sigmask(int signum)
{
	return (1UL << ((signum - 1) % ULONG_WIDTH));
}

unsigned long int ft_sigword(int signum)
{
	return (signum - 1) / ULONG_WIDTH;
}

int ft_sigemptyset(kernel_sigset_t *set)
{
	//for (size_t i = 0; i < _SIGSET_NWORDS; i++) {
	//	set->__val[i] = 0;
	//}
	ft_memset(set->__val, 0, sizeof(set->__val));
	return 0;
}

void ft_sigaddset(kernel_sigset_t *set, int signum)
{
	set->__val[ft_sigword(signum)] |= ft_sigmask(signum);
}
