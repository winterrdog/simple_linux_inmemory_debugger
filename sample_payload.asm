global _start

_start:
    ; save the previous register content on the stack to 
    ; prevent inconsistency across func calls
    push rdi
    push rsi
    push rdx
    push rax

    mov rdx, len    ; length of message
    lea rsi, BYTE [rel msg]    ; message to print{like assigning a ptr, what to point to, in C}
    mov rdi, 0x1    ; fd=stdout
    mov rax, 0x1    ; sys_write
    syscall        ; run the syscall/ call kernel

    ;; exit program
    ; mov rax,0x3c
    ; mov rdi,0x0
    ; syscall

    pop rax
    pop rdx
    pop rsi
    pop rdi
    
    ret



msg: db "HACKY has pwned this machine!",0xa

len: equ $ - msg     ; length of our string!
