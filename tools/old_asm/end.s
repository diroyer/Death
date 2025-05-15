global end

section .text

end:
	; exit
	mov rax, 60
	xor rdi, rdi
	syscall
