GLOBAL Start
GLOBAL GarouStart
GLOBAL GarouRipEnd

EXTERN GarouLdr

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