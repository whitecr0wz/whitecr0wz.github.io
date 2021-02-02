---
layout: post
title: x86_64 Egghunter
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have a close look at Egghunters. 

An Egghunter is a form of malware, commonly used during Exploit-Development sessions in order to process bigger shellcode when there is low space available. The process is quite 
simple, this will search for a specific tag within the memory. When found, the flow will be passed upon the instructions following the tag, executing the original shellcode. 

The third assignment from the seven requires the creation of an Egghunter through the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required to test such.

##### Methods

In order to create an Egghunter shellcode, there are several paths. However, as the time goes on, newer techniques are implemented that make shellcoding easier. I have chosen to 
cover a modern method which is fast, and tends to be very small regarding size. This method obeys the following procedure:

+ RCX is chosen as the register to compare with the tag.
+ The tag is saved on RBP. This tag will not be hardcoded.
+ RCX is incremented.
+ RBP is compared against RCX.
+ If the Zero flag (ZF) hasn't been set, repeat this loop.
+ Give RCX the value of RCX+8, in order to jump exactly within the shellcode and not the tag.
+ Jump to RCX.

Code:

```term
global _start

_start:

       inc rdx                     ; Increments RDX.
       push rdx                    ; Pushes the value of RDX into the Stack.
       pop rcx                     ; Pops the top of the Stack into RCX.

       mov rbp, 0x5756575657565756 ; Original tag should be 0x4645464546454645.
       mov rbx, 0x1111111111111111 ; Gives the value "0x1111111111111111" to RBX.
       sub rbp, rbx                ; RBP is substracted by RBX.

main:

       inc rcx                     ; RCX is incremented.
       cmp rbp, [rcx]              ; RBP is compared against RCX.
       jnz main                    ; Jump to main if the Zero flag (ZF) hasn't been set.

       lea rcx, [rcx + 8]          ; Copy RCX+8 into RCX.

       jmp rcx                     ; Jump into RCX.
```

Let's assemble this, link it, and get its shellcode.

