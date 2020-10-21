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

Through the course of this post i will use FTPDummy! FTP Client to explain such concept. I have made a previous post regarding such software [here](https://whitecr0wz.github.io/posts/ftp-dummy/).

![](/assets/img/Code_Cave/1.png)
