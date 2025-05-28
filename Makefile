
override name := Death

override src_dir := src

override srcs := famine.c \
				 data.c \
				 map.c \
				 bss.c \
				 utils.c \
				 pestilence.c \
				 war.c \
				 daemon.c \
				 syscall.c \
				 death.c \
				 signale.c \
				 exit.c

# add prefix to srcs
override srcs := $(addprefix $(src_dir)/, $(srcs))

override objs := $(srcs:%.c=%.o) 

override deps := $(srcs:%.c=%.d)


override cflags := -fpic -nostdlib -I./inc -fcf-protection=none -O0 -std=gnu11 \
					-g -fno-jump-tables \
					-Wno-unused-function \
					-Wall -Wextra -Werror -Wpedantic

override depflags = -MT $@ -MMD -MF $(src_dir)/$*.d

override ldflags := -nostdlib -z noexecstack
def := -DDEBUG -DLOGGER

.PHONY: all clean fclean re

all: $(name)

$(name): $(objs)
	gcc $^ -o $(name) $(ldflags)

-include $(deps)
src/%.o: src/%.c Makefile
	gcc $(cflags) $(depflags) -c $< -o $@ -D _GNU_SOURCE -D PAGE_SIZE=4096 ${def}

clean:
	@rm -vf $(objs) $(deps)

fclean: clean
	@rm -vf $(name) 

re: fclean all
