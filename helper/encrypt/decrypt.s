bits 64
default rel

; Fonction decrypt en assembleur x86-64
; Paramètres:
;   rdi = pointeur vers les données (uint8_t *data)
;   rsi = taille des données (size_t size)
;   rdx = clé de chiffrement (uint64_t key)
; Retourne:
;   rax = 0 en cas de succès, -1 en cas d'échec

; Fonction decrypt en assembleur x86-64
; Paramètres:
;   rdi = pointeur vers les données (uint8_t *data)
;   rsi = taille des données (size_t size)
;   rdx = clé de chiffrement (uint64_t key)
; Retourne:
;   rax = 0 en cas de succès, -1 en cas d'échec

bits 64
default rel

section .text
global decrypt

decrypt:
    ; Préserver les registres qui doivent être sauvegardés selon l'ABI
    ;push rbp
    ;mov rbp, rsp
    ;push rbx
    ;push r12
    ;push r13
    ;push r14
    ;push r15

    ; Initialiser les registres avec les paramètres
    mov r12, rdi          ; r12 = data
    mov r13, rsi          ; r13 = size
    mov r14, rdx          ; r14 = key original
    xor rcx, rcx          ; rcx = i (compteur de boucle)

    ; Vérifier si size est 0
    test r13, r13
    jz .success           ; Si size est 0, rien à faire, retourner 0

.loop:
    ; Calculer l'index et la clé pour l'itération actuelle
    ; Il faut d'abord calculer la même clé qu'à l'étape d'encryption
    mov r15, rcx          ; r15 = i
    mov rbx, r14          ; rbx = clé originale

    ; Appliquer les transformations de clé pour chaque itération précédente
    xor rax, rax
    cmp r15, 0
    je .apply_key         ; Si c'est la première itération, pas de transformations préalables

.key_transform_loop:
    ; Rotation: key = (key >> 7) | (key << (64 - 7))
    mov rdx, rbx
    shr rdx, 7
    mov r11, rbx
    shl r11, 57           ; 64 - 7 = 57
    or rdx, r11
    
    ; XOR: key ^= 0x9e3779b97f4a7c15
    mov r10, 0x9e3779b97f4a7c15
    xor rdx, r10
    
    mov rbx, rdx          ; Mettre à jour la clé pour la prochaine itération
    
    inc rax
    cmp rax, r15
    jl .key_transform_loop

.apply_key:
    ; Calculer k = (key >> (8 * (i % 8))) & 0xFF
    mov rax, r15          ; rax = i
    xor rdx, rdx          ; Mettre rdx à 0 pour la division
    mov r10, 8
    div r10               ; rdx = i % 8
    
    ; Calculer le nombre de bits à décaler (8 * (i % 8))
    mov rcx, rdx          ; rcx = i % 8
    imul rcx, 8           ; rcx = 8 * (i % 8)
    
    mov rdx, rbx          ; rdx = key actuelle
    mov r10, rdx          ; Sauvegarder la clé dans r10
    
    ; Utiliser cl (partie basse de rcx) pour l'opération de décalage
    shr r10, cl           ; r10 = key >> (8 * (i % 8))
    and r10b, 0xFF        ; r10b = k = (key >> (8 * (i % 8))) & 0xFF
    
    ; Maintenant décrypter: d'abord soustraire k, puis XOR avec k
    movzx rax, byte [r12 + r15]  ; rax = data[i], avec zero-extension
    sub al, r10b                 ; al = data[i] - k
    xor al, r10b                 ; al = (data[i] - k) ^ k
    mov byte [r12 + r15], al     ; data[i] = al
    
    ; Incrémenter le compteur et vérifier si on a fini
    mov rcx, r15                 ; Restaurer rcx comme compteur
    inc rcx
    cmp rcx, r13
    jl .loop

.success:
    ; Succès, retourner 0
    xor rax, rax
    jmp .return

.return:
    ; Restaurer les registres sauvegardés
    ;pop r15
    ;pop r14
    ;pop r13
    ;pop r12
    ;pop rbx
    ;pop rbp
    ret
