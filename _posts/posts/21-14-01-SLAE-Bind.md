---
layout: post
title: Vulnserver Assignment 1: Creation of a Bind TCP Shell 
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

### Introduction

"Remote shellcode is used when an attacker wants to target a vulnerable process running on another machine on a local network, intranet, or a remote network. If successfully executed, the shellcode can provide the attacker access to the target machine across the network. Remote shellcodes normally use standard TCP/IP socket connections to allow the attacker access to the shell on the target machine. Such shellcode can be categorized based on how this connection is set up: if the shellcode establishes the connection, it is called a "reverse shell" or a connect-back shellcode because the shellcode connects back to the attacker's machine. On the other hand, if the attacker establishes the connection, the shellcode is called a bindshell because the shellcode binds to a certain port on the victim's machine. A third, much less common type, is socket-reuse shellcode. This type of shellcode is sometimes used when an exploit establishes a connection to the vulnerable process that is not closed before the shellcode is run. The shellcode can then re-use this connection to communicate with the attacker. Socket re-using shellcode is more elaborate, since the shellcode needs to find out which connection to re-use and the machine may have many connections open." - Wikipedia

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_1).
