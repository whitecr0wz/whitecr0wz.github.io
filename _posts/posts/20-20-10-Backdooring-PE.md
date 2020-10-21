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
