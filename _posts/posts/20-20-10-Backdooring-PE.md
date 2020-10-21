---
layout: post
title: Backdooring PE Files through Code Caves
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

### Introduction

Building malware is a topic which has always been from great interest to me. However, injecting malicious code within benign software seems a very concerning yet engrossing concept. PE Injection is pretty much the aforementioned example, embedding shellcode into a non-used fragment of code within a program which is commonly not flagged as a program.

Normally, in order to achieve PE Injection or simply backdooring, there are two methods:

+ Adding a new header with empty space into the program, through programs such as PE Lord or CFF Explorer.
+ Using a Code Cave. An original section of the code which is not relevant to the execution.

During this tutorial, i will exhibit the latter, this is due to the fact that adding a new header is very noisy regarding space when read by AV Software. On the other hand, Code Caves do not change space whatsoever, as the space is already being used, and there are no new headers.

##### Time to get our hands dirty.

Through the course of this post i will use FTPDummy! FTP Client to explain such concept, due to the reason that it is lightweight, easy to use and does not have ASLR enabled on the main module, making things a little easier. I have made a previous post regarding such software [here](https://whitecr0wz.github.io/posts/ftp-dummy/).

![](/assets/img/Code_Cave/1.png)
###### Main menu of FTPDummy!

In addition, i will be using VirusTotal in order to check how many AV Software are capable of detecting the PE File.

![](/assets/img/Code_Cave/2.png)
###### FTPDummy! when checked by VirusTotal.

Furthermore, when it comes to finding code caves, i have chosen [pycave.py](https://github.com/axcheron/pycave), it requires Python 3.8 and the module [PEFile](https://pypi.org/project/pefile/).

![](/assets/img/Code_Cave/3.png)
###### Revealed Code Caves

As revealed on the image, there are several Code Caves in the .rsrc section. In order to not worry at all with space issues, i'll use 0x0052715E as it has 2814 bytes of spaces, according to pycave.py.

#### The Process

Before stepping into how the backdooring is done, i think the whole process should be explained clearly.

In order to backdoor, the following steps must be taken:

+ The flow must be hijacked. This can be achieved through several methods I.E Replacing the entry point instruction for a JMP instruction pointing into the desired Code Cave. Also, more specific hijacking can be achieved, such as executing the JMP when executing a section of the code (I.E: Open Help, URL, Credits, or any other button). Nevertheless, due to the complexity of this last technique, it shall be reserved for the following post.

Once EIP points towards the Code Cave, the next combination of instructions must be assembled.

+ PUSHAD/PUSHFD instructions. These will save our instructions so that they are aligned later on. It is essential for the registers to be aligned so that the instructions work perfectly according to the value of these.
+ The Shellcode. Shellcode, we are used to it. Some modifications may need to be issued, such as the removal of the last instruction in some cases, as it tends to crash the flow and the modification of a byte which waits for the shellcode to exit for the main program to return its original flow.
+ Alignment. The ESP Register must be restored to its old value.
+ POPFD/POPAD. These instructions will restore our flags.
+ As when assembling the JMP on the entry point instruction some other instructions were replaced, these must be assembled once again so that the code runs as intended and does not crash!

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
