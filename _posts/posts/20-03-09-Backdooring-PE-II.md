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

Today, I will be explaining how to backdoor PE Files with the addition of user interaction and encoding as well. Furthermore, in order to replay the concept, the application [recmp3](https://sourceforge.net/projects/recmp3/) will be used, as it is lightweight program which has several Code Caves with ASLR disabled within the affected zone. 

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
