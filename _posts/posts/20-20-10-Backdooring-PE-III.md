---
layout: post
title: Beating ASLR & NX/DEP without Additional PE Headers nor Code Caves (VOL:III)
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

### Introduction

You find yourself reading the third volume of the "PE File Backdooring" series. As a result of such, I highly recommend reading the [first](https://whitecr0wz.github.io/posts/Backdooring-PE/) and [second](https://whitecr0wz.github.io/posts/Backdooring-PE-II/) blog post of the series, as it may help understanding the shown material on this post.

Today, I will be explaining how to backdoor PE Files when heavy protections such as ASLR and NX/DEP are present without altering the binary at all.
Furthermore, in order to replay the concept, the well-known [task manager](https://en.wikipedia.org/wiki/Task_Manager_(Windows)) will be employed, due to the reason that it has all protections enabled and as it is a common executable.

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

Interesting, we see several places in which we could inject our payload. However, this is actually not possible, as NX/DEP would prevent our instructions from being executed. Of course, we could just change the properties of certain sections such as .data or .rsrc, but this is actually found off the bounds of this post, isn't it? We need to circumvent such environment without changing the binary too much.

Let's check the enabled protections.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/1.png)

As aforementioned, everything seems enabled.

As we are unable to use a the addition of a PE Header and a Code Cave, we are left with pretty scarce options. Nevertheless, if checked on most binaries, at the bottom of the stack, we may find unused data that is partially executable.

![](/assets/img/Backdooring%20PE%20Files%20(VOL%20III)/2.png)

It isn't quite much, perhaps among 500 bytes, but it sure is enough to fit our payload and execute it. Sadly, encoding is not available in such scenarios, as the section is too privileged for certain encoding characters which are obligatory.
