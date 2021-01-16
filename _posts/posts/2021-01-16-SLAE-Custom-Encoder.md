---
layout: post
title: Custom Encoder
date: 2021-01-14 18:18:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at a Custom Encoder. 


The fourth assignment from the seven requires the creation of a Custom Encoder, similar to the one shown in the course as the "Insertion Encoder". This should be written in the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required that such is tested later on the C format.

##### The Encoder

As for the encoder itself, I have chosen to concanate the three main techniques regarding encoding during the course, therefore, the encoder obeys the following procedure:

+ XORs every opcode of the shellcode by 46.
+ Performs a NOT operation on every opcode of the shellcode.
+ Inserts an additional 0x45 byte for every opcode.

Having the knowledge of such course of action allows us to understand that the decoder should follow the exact same process but on reverse:

+ Remove the an additional 0x45 byte for every opcode and restore the encoded shellcode.
+ Perform a NOT operation on every opcode of the shellcode.
+ XOR every opcode of the shellcode by 46.

#### The encoder

```term
#!/usr/bin/python

shellcode = (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\xb0\x0b\xcd\x80"
)

encoded = ""
encoded2 = ""

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :

                                y = ~x^0x46

                                encoded += '\\x'
                                encoded += '%02x' % (y & 0xFF)
                                encoded += '\\x%02x' % 0x45

                                encoded2 += '0x'
                                encoded2 += '%02x,' % (y & 0xFF)
                                encoded2 += '0x%02x,' % 0x45


print '"' + encoded + '"'

print encoded2

print 'Len: %d' % len(bytearray(shellcode))
```

Let's encode the shellcode:

```term
whitecr0wz@SLAE:~/assembly/assignments/Assignment_4$ python custom_encoder.py 
Encoded shellcode ...
"\x88\x45\x79\x45\xe9\x45\xd1\x45\x96\x45\x96\x45\xca\x45\xd1\x45\xd1\x45\x96\x45\xdb\x45\xd0\x45\xd7\x45\x30\x45\x5a\x45\xe9\x45\x30\x45\x5b\x45\x09\x45\xb2\x45\x74\x45\x39\x45"
0x88,0x45,0x79,0x45,0xe9,0x45,0xd1,0x45,0x96,0x45,0x96,0x45,0xca,0x45,0xd1,0x45,0xd1,0x45,0x96,0x45,0xdb,0x45,0xd0,0x45,0xd7,0x45,0x30,0x45,0x5a,0x45,0xe9,0x45,0x30,0x45,0x5b,0x45,0x09,0x45,0xb2,0x45,0x74,0x45,0x39,0x45,
Len: 22
whitecr0wz@SLAE:~/assembly/assignments/Assignment_4$
```

Good, let's create the skeleton code:

```term
global _start

section .text

_start:

      jmp short master               ; Jumps to master

main:

      pop ebp                        ; Pops the value of the shellcode into ebp
      mov esi, ebp                   ; Copies the value from ebp to esi

master:

      call main                      ; Calls to main and pops shellcode into the stack

      shellcode: db 0x88,0x45,0x79,0x45,0xe9,0x45,0xd1,0x45,0x96,0x45,0x96,0x45,0xca,0x45,0xd1,0x45,0xd1,0x45,0x96,0x45,0xdb,0x45,0xd0,0x45,0xd7,0x45,0x30,0x45,0x5a,0x45,0xe9,0x45,0x30,0x45,0x5b,0x45,0x09,0x45,0xb2,0x45,0x74,0x45,0x39,0x45
```

Right now, the flow jumps to the master section and calls main, pushing the value of shellcode into the stack and popping into EBP. Furthermore, this value is copied into ESI, 
this will be essential when it comes to the following sections of XORing and NOT decoding the instructions, as the ESI value will have to be zeroed, therefore, EBP being a 
backup register.

Now, the following steps are the same as when it comes to any insertion decoder:

+ Point EDI to the additional bytes.
+ Start a counter for the loop. (44 bytes in our case)
+ Point BL to the additional bytes.
+ XOR BL by the additional bytes.
+ Point BL to the following byte, which should be the intended.
+ Copy the value of BL into EDI, slowly restoring the original order.
+ Increment EDI in order to repeat the process.
+ AL is incremented by 2, once again to repeat the process.
+ Start the loop

```term
      lea edi, [esi + 1]             ; Points to the 0x45 byte

      xor eax, eax                   ; Zeroes out EAX
      xor ebx, ebx                   ; Zeroes out EBX

      mov cl, 44                     ; Stores counter (44 bytes)
      mov al, 1                      ; Makes AL hold value 1 for later calculations.
      
decode:

      mov bl, byte [esi + eax]       ; Points to 0x45
      xor bl, 0x45                   ; Turns 0x45 into 0x00
      mov bl, byte [esi + eax + 1]   ; Grabs intended value
      mov byte [edi], bl             ; Replaces 0x00 for the intended value
      inc edi                        ; Increments EDI, holding next 0xAA for replacement
      add al, 2                      ; Adds 2 in order to continue the process
      loop decode                    ; Starts loop

#### EndGame



### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_4).
