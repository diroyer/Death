default rel
global _syscall

section .text
_syscall:
	mov rax, rdi
	mov rdi, rsi
	mov rsi, rdx
	mov rdx, rcx
	mov r10, r8
	mov r8, r9
	mov r9, [rsp + 8]
	syscall

	cmp rax, 0
	jl .error
	ret

.error:
	mov rax, -1
	ret


;	mov rdi, -4095
;	cmp rdi, rax
;
;	jae end_syscall
;
;error:
;	mov rax, -1
;
;end_syscall:
;	ret
;
