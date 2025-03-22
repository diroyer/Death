
override name := Death

override src_dir := src

override srcs := famine.c \
				 data.c \
				 map.c \
				 bss.c \
				 utils.c \
				 text.c \
				 pestilence.c \
				 war.c \
				 daemon.c \
				 syscall.c \
				 death.c \

override asms :=  decrypt.s \
				  end.s

# add prefix to srcs
override srcs := $(addprefix $(src_dir)/, $(srcs))
override asms := $(addprefix $(src_dir)/, $(asms))

override objs := $(srcs:%.c=%.o) $(asms:%.s=%.o)

override deps := $(srcs:%.c=%.d)


override cflags := -fpic -nostdlib -I./inc -fcf-protection=none -g \
					-Wall -Wextra -Werror -Wpedantic -std=c17
# -no-pie -fno-stack-protector -fno-builtin 
#-fpic -fno-stack-protector -nodefaultlibs -fno-builtin -fno-omit-frame-pointer -pie -static

override depflags = -MT $@ -MMD -MF $(src_dir)/$*.d

override sflags := -f elf64

override ldflags := -nostdlib -z noexecstack
#-pie -static
def := -DDEBUG -D_GNU_SOURCE


.PHONY: all clean fclean re

all: $(name)

$(name): $(objs)
	gcc $^ -o $(name) $(ldflags)

-include $(deps)
src/%.o: src/%.c Makefile
	gcc $(cflags) $(depflags) -c $< -o $@ $(def)

src/%.o: src/%.s Makefile
	nasm $(sflags) -o $@ $<

clean:
	@rm -vf $(objs) $(deps)

fclean: clean
	@rm -vf $(name) 
#'.cache' 
#'compile_commands.json'

re: fclean all
