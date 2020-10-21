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

![](/assets/img/Code_Cave/1.png)
