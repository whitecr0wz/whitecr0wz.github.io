layout: post
title: Reverse TCP Shell 
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---
#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at Linux Reverse Shells. 

A Reverse shell is a form of malware which grants remote access to a system through a shell. However, differentiating from its peer the Bind shell, arranging a specific connection on a trivial address, instead of binding to a local port of the compromised system.

The second assignment from the seven requires the creation of a Reverse Shell through the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required to write a wrapper in any language of preference that is capable of 
easily configuring the port.

#### Theory 

In order to create a Reverse Shell, 4 main functions are required:

+ Socket

+ Dup2

+ Connect

+ Execve

#### Time to stick our hands into the mud

The first thing required is to clean the registers, as when we execute our program, it will work as a charm, however, when introduced into a real program within a context of 
binary exploitation with different variables that alter the registers, it may not. Due to this, it's better to have a set of instructions that clean the registers that will be 
employed:

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

##### Connect

###### 

#### EndGame

![](/assets/img/SLAE/SLAE32/Assignment_2/2.png)

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_2).
