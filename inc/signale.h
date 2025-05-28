#ifndef SIGNALE_H
#define SIGNALE_H

#include <signal.h>

typedef struct {
	unsigned long int __val[_SIGSET_NWORDS];
} kernel_sigset_t;

unsigned long int ft_sigmask(int signum);
unsigned long int ft_sigword(int signum);
int ft_sigemptyset(kernel_sigset_t *set);
void ft_sigaddset(kernel_sigset_t *set, int signum);

//#define NSIG_WORDS (NSIG / (8 * sizeof(unsigned long int)))
//#define NSIG_WORDS (1024 / (8 * sizeof(unsigned long int)))

#endif /* SIGNAL_H */
