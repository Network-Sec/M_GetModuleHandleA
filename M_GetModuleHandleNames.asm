section .text
global M_GetModuleHandleA

M_GetModuleHandleA:
    ; Extended version that also returns DllNames: void __cdecl M_GetModuleHandleA(uint64_t* addr_array, int* idx, wchar_t** name_array)
    xor r9, r9  ; Clear r9 for index

    ; Get PEB and Ldr
    mov rax, gs:[30h]
    mov rdi, [rax+60h]

    ; First Flink
    mov r12, [rdi+18h]
    add r12, 20h
    mov rbx, [r12]

    ; Check if there's at least one module
    cmp rbx, 0
    je .end_loop

    ; Get DllBase for first entry
    mov rax, [rbx+20h]
    
    ; Store DllBase in the array
    mov [rcx + r9*8], rax

    ; Store process name in r13
    mov r13, [rbx+40h] ; r13 = FullDllName.Buffer
    
    ; Store it in output array
    mov r11, r8         ; r11 points to the output array
    mov r14, r13        ; rsi points to the FullDllName.Buffer

    ; Store the pointer to FullDllName.Buffer in the output array
    mov [r11 + r9*8], r14

    inc r9
    
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

    ; Store dllname in r13
    mov r13, [rdi+40h]
    
     ; Store it in output array
    mov r11, r8         ; r11 points to the output array
    mov r14, r13        ; rsi points to the FullDllName.Buffer

    ; Store the pointer to FullDllName.Buffer in the output array
    mov [r11 + r9*8], r14

    inc r9

    ; Update loop variables
    mov rbx, rdi
    jmp .loop

.end_loop:
    ; Add an entry of 0 as last entry in the array
    mov qword [rcx + r9*8], 0
    mov qword [r8 + r9*8], 0

    ; Store the number of entries back to idx
    mov [rdx], r9      ; Store the count of entries found in idx

    ; Done
    ret

; nasm -f win64 -o M_GetModuleHandleA.obj .\M_GetModuleHandleA.dllasm
; link /dll /out:M_GetModuleHandleA.dll M_GetModuleHandleA.obj /export:M_GetModuleHandleA /entry:M_GetModuleHandleA /implib:M_GetModuleHandleA.lib
