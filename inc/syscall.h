#ifndef SYSCALL_H
# define SYSCALL_H

# include <sys/syscall.h>

extern long _syscall(long number, ...);
/* unistd.h */
#define write(_fd, _ptr, _size) (_syscall(SYS_write, (_fd), (_ptr), (_size)))
#define close(_fd) (_syscall(SYS_close, (_fd)))
#define pread(_fd, _buf, _count, _offset) (_syscall(SYS_pread64, (_fd), (_buf), (_count), (_offset)))
#define open(_filename, ...) (_syscall(SYS_open, _filename, __VA_ARGS__))
#define read(_fd, _buf, _count) (_syscall(SYS_read, (_fd), (_buf), (_count)))
#define unlink(_pathname) (_syscall(SYS_unlink, (_pathname)))
#define chdir(_path) (_syscall(SYS_chdir, (_path)))
#define pipe(_pipefd) (_syscall(SYS_pipe, (_pipefd)))
#define execve(_filename, _argv, _envp) (_syscall(SYS_execve, (_filename), (_argv), (_envp)))
#define fsync(_fd) (_syscall(SYS_fsync, (_fd)))

/* fcntl.h */
#define fcntl(_fd, ...) (_syscall(SYS_fcntl, (_fd), __VA_ARGS__))
#define flock(_fd, _op) (_syscall(SYS_flock, (_fd), (_op)))
#define ftruncate(_fd, _length) (_syscall(SYS_ftruncate, (_fd), (_length)))

/* sys/mman.h */
#define mmap(_addr, _length, _prot, _flags, _fd, _offset) (_syscall(SYS_mmap, (_addr), (_length), (_prot), (_flags), (_fd), (_offset)))
#define munmap(_addr, _length) (_syscall(SYS_munmap, (_addr), (_length)))
#define mprotect(_addr, _length, _prot) (_syscall(SYS_mprotect, (_addr), (_length), (_prot)))

/* sys/stat.h */
#define fstat(_fd, _statbuf) (_syscall(SYS_fstat, (_fd), (_statbuf)))

/* sys/wait.h */
#define fork() (_syscall(SYS_fork))
#define waitid(_idtype, _id, _infop, _options) (_syscall(SYS_waitid, (_idtype), (_id), (_infop), (_options)))

/* signal.h */
#define sigaction(_signum, _act, _oldact, _size) (_syscall(SYS_rt_sigaction, (_signum), (_act), (_oldact), (_size)))

/* unistd.h */
#define setsid() (_syscall(SYS_setsid))
#define setuid(_uid) (_syscall(SYS_setuid, (_uid)))
#define setpgid(_pid, _pgid) (_syscall(SYS_setpgid, (_pid), (_pgid)))

/* sys/socket.h */
#define socket(_domain, _type, _protocol) (_syscall(SYS_socket, (_domain), (_type), (_protocol)))
#define bind(_sockfd, _addr, _addrlen) (_syscall(SYS_bind, (_sockfd), (_addr), (_addrlen)))
#define listen(_sockfd, _backlog) (_syscall(SYS_listen, (_sockfd), (_backlog)))
#define setsockopt(_sockfd, _level, _optname, _optval, _optlen) (_syscall(SYS_setsockopt, (_sockfd), (_level), (_optname), (_optval), (_optlen)))
#define accept(_sockfd, _addr, _addrlen) (_syscall(SYS_accept, (_sockfd), (_addr), (_addrlen)))
#define shutdown(_sockfd, _how) (_syscall(SYS_shutdown, (_sockfd), (_how)))

/* unistd.h */
#define nanosleep(_duration, _rem) (_syscall(SYS_nanosleep, (_duration), (_rem)))
#define ptrace(_op, _pid, _addr, _data) (_syscall(SYS_ptrace, (_op), (_pid), (_addr), (_data)))
#define readlink(_pathname, _buf, _bufsiz) (_syscall(SYS_readlink, (_pathname), (_buf), (_bufsiz)))
#define prctl(_option, ...) (_syscall(SYS_prctl, (_option), __VA_ARGS__))
#define dup2(_oldfd, _newfd) (_syscall(SYS_dup2, (_oldfd), (_newfd)))
#define umask(_mask) (_syscall(SYS_umask, (_mask)))
#define exit(_status) (_syscall(SYS_exit, (_status)))
#define getdents64(_fd, _dirp, _count) (_syscall(SYS_getdents64, (_fd), (_dirp), (_count)))

/* sys/time.h */
#define gettimeofday(_tv, _tz) (_syscall(SYS_gettimeofday, (_tv), (_tz)))

/* sys/shm.h */
#define shmget(_key, _size, _shmflg) (_syscall(SYS_shmget, (_key), (_size), (_shmflg)))
#define shmat(_shmid, _shmaddr, _shmflg) (_syscall(SYS_shmat, (_shmid), (_shmaddr), (_shmflg)))
#define shmdt(_shmaddr) (_syscall(SYS_shmdt, (_shmaddr)))

/* sys/getrandom.h */
#define getrandom(_buf, _count, _flags) (_syscall(SYS_getrandom, (_buf), (_count), (_flags)))


# define STR(_str) ((char[]){_str})

#endif
