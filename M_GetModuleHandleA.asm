default rel
section .text
global M_GetModuleHandleA

M_GetModuleHandleA:
    ; rcx contains the address of the passed-in array
    ; rdx contains the address of the passed-in idx 

    xor r9, r9  ; Clear r9 for index

    ; Get PEB and Ldr
    mov rax, gs:[30h]
    mov rdi, [rax+60h]

    ; First Flink
    mov r12, [rdi+18h]
    add r12, 20h
    mov rbx, [r12]

    ; Get DllBase for first entry
    mov rax, [rbx+20h]

    ; Store DllBase in the array
    mov [rcx + r9*8], rax
    inc r9

    ; Store process name in r13
    mov r13, [rbx+40h]

    ; Store first DllBase in r10 
    mov r10, rax  

.loop:
    ; Next Flink
    mov rdi, [rbx]

    ; Break if we have looped back to the first entry
    mov rax, [rdi+20h]
    cmp rax, r10
    je .end_loop

    ; Get DllBase for next entry
    mov rax, [rdi+20h]
    
    ; Store DllBase in the array
    mov [rcx + r9*8], rax
    inc r9

    ; Store dllname in r13
    mov r13, [rdi+40h]

    ; Update loop variables
    mov rbx, rdi
    jmp .loop

.end_loop:
    ; Add an entry of 0 as last entry in the array
    mov qword [rcx + r9*8], 0

    ; Done
    ret 
