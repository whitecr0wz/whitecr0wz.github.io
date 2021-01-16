---
layout: post
title: Egghunter
date: 2021-01-16 16:31:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at Egghunters. 

An Egghunter is a form of malware, commonly used during Exploit-Development sessions in order to process bigger shellcode when there is low space available. The process is quite simple, this will search for a specific tag within the memory. When found, the flow will be passed upon the instructions following the tag, executing the original shellcode. 

The third assignment from the seven requires the creation of an Egghunter through the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required to test such.

##### Methods

In order to create an Egghunter shellcode, there are several paths. However, as the time goes on, newer techniques are implemented that make shellcoding easier. I have chosen to cover a modern method which is fast, and tends to be very small regarding size. This method follows procedure:

+ The tag is saved on ESI
+ EBX is incremented
+ The value of EBX is compared with ESI. If positive, this should set the Zero Flag (ZF)
+ Repeat this process through a jump if not zero (JNZ) condition.
+ Jump into EBX.

It is quite important to note that the tag does not contain an opocode that an interfere with our egghunter, such as an INC ESI (46), or DEC EBX (4B). The tag chosen is 45474547 (GEGE).

Code:

```term
global _start

_start:

      mov esi, 0x45474547       ; Moves the tag GEGE into ESI

main:

      inc ebx                   ; Increments EBX for comparison.
      cmp dword [ebx], esi      ; Compares EBX with ESI, that contains the tag. If they contain the same value, set the Zero flag (ZF).
      jne main                  ; Jumps to main to repeat the loop until the Zero flag (ZF) is set.
      push ebx                  ; Pushes the value of EBX into the stack.
      ret                       ; Pops it into the EIP.
```

#### EndGame


### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_3).
