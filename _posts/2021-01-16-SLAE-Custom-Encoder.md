---
title: Custom Encoder 
author: fwinsnes
date: 2021-01-17 13:44:00 +0800
categories: [SLAE]
tags: [assembly, shellcoding]
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at a Custom Encoder. 


The fourth assignment from the seven requires the creation of a Custom Encoder, similar to the one shown in the course as the "Insertion Encoder". This should be written in the 
Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required that such is tested later on the C format.

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
"\x88\x45\x79\x45\xe9\x45\xd1\x45\x96\x45\x96\x45\xca\x45\xd1\x45\xd1\x45\x96\x45\xdb\x45\xd0\x45\xd7\x45\x30\x45\x5a\x45\xe9\x45\x30\x45\x5b\x45\x09\x45\xb2\x45\x74\x45\x39\x45
"
0x88,0x45,0x79,0x45,0xe9,0x45,0xd1,0x45,0x96,0x45,0x96,0x45,0xca,0x45,0xd1,0x45,0xd1,0x45,0x96,0x45,0xdb,0x45,0xd0,0x45,0xd7,0x45,0x30,0x45,0x5a,0x45,0xe9,0x45,0x30,0x45,0x5b,0x
45,0x09,0x45,0xb2,0x45,0x74,0x45,0x39,0x45,
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
+ Start the loop.

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
      inc edi                        ; Increments EDI, holding next 0x45 for replacement
      add al, 2                      ; Adds 2 in order to continue the process
      loop decode                    ; Starts loop
```

Great! By now our shellcode should have the additional 0x45 bytes removed, the following step is to clean ESI and restore its value by copying the EBP register's one! 
Furthermore, it is left for use to set the counter once again! This time to the half of the shellcode, as the additional bytes have been removed. 

```term
      mov cl, 22                     ; Stores counter (22 bytes)
      xor esi, esi                   ; Zeroes out ESI
      mov esi, ebp                   ; Copies the value from ebp to esi
```

The next step should be executing the NOT operation. And once again, clean the value of ESI and restore its value!

The procedure of the NOT operation should be the pollowing:

+ Perform a NOT operation on the value of ESI.
+ Increment ESI, pointing to the next byte.
+ Continue the loop.

```term
decode2:

      not byte [esi]                 ; Performs a NOT operation on the value pointed by ESI
      inc esi                        ; Increments ESI, therefore performing a NOT operation on every opcode
      loop decode2                   ; Starts loop

      mov cl, 22                     ; Stores counter (22 bytes)
      xor esi, esi                   ; Zeroes out ESI
      mov esi, ebp                   ; Copies the value from ebp to esi
```

Finally, at last we have to XOR the remaining part of the shellcode by 0x46.

The procedure of the XOR operation should be the pollowing:

+ Perform a XOR operation with 0x46 on the value of ESI.
+ Increment ESI, pointing to the next byte.
+ Continue the loop.
+ Once this is finished, jump to the fully decoded shellcode.

```term
decode3:

      xor byte [esi], 0x46           ; Performs a XOR operation between the value of ESI and 0x46
      inc esi                        ; Increments ESI, therefore performing aXOR operation on every opcode
      loop decode3                   ; Starts loop
      jmp short shellcode            ; Jumps to the shellcode

```

Let's test this encoder within the C format:

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x38\x5d\x89\xee\x8d\x7e\x01\x31\xc0\x31\xdb\xb1\x2c\xb0\x01\x8a\x1c\x06\x80\xf3\x45\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\xe2\xef\xb1\x16\x31\xf6\x89\xee\xf6\x16\x46\xe2\xfb
\xb1\x16\x31\xf6\x89\xee\x80\x36\x46\x46\xe2\xfa\xeb\x05\xe8\xc3\xff\xff\xff\x88\x45\x79\x45\xe9\x45\xd1\x45\x96\x45\x96\x45\xca\x45\xd1\x45\xd1\x45\x96\x45\xdb\x45\xd0\x45\xd7\
x45\x30\x45\x5a\x45\xe9\x45\x30\x45\x5b\x45\x09\x45\xb2\x45\x74\x45\x39\x45";

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame

```term
whitecr0wz@SLAE:~/assembly/assignments/Assignment_4$ gcc custom_insertion.c -o custom_insertion -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE:~/assembly/assignments/Assignment_4$ ./custom_insertion 
Shellcode Length:  107
$
```

Complete code:

```term
global _start

section .text

_start:

      jmp short master               ; Jumps to master

main:

      pop ebp                        ; Pops the value of the shellcode into ebp
      mov esi, ebp                   ; Copies the value from ebp to esi

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

      mov cl, 22                     ; Stores counter (22 bytes)
      xor esi, esi                   ; Zeroes out ESI
      mov esi, ebp                   ; Copies the value from ebp to esi

decode2:

      not byte [esi]                 ; Performs a NOT operation on the value pointed by ESI
      inc esi                        ; Increments ESI, therefore performing a NOT operation on every opcode
      loop decode2                   ; Starts loop

      mov cl, 22                     ; Stores counter (22 bytes)
      xor esi, esi                   ; Zeroes out ESI
      mov esi, ebp                   ; Copies the value from ebp to esi

decode3:

      xor byte [esi], 0x46           ; Performs a XOR operation between the value of ESI and 0x46
      inc esi                        ; Increments ESI, therefore performing aXOR operation on every opcode
      loop decode3                   ; Starts loop
      jmp short shellcode            ; Jumps to the shellcode

master:

      call main                      ; Calls to main and pops shellcode into the stack

      shellcode: db 0x88,0x45,0x79,0x45,0xe9,0x45,0xd1,0x45,0x96,0x45,0x96,0x45,0xca,0x45,0xd1,0x45,0xd1,0x45,0x96,0x45,0xdb,0x45,0xd0,0x45,0xd7,0x45,0x30,0x45,0x5a,0x45,0xe9,0x45,0x30,0x45,0x5b,0x45,0x09,0x45,0xb2,0x45,0x74,0x45,0x39,0x45
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_4).
