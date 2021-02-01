---
layout: post
title: Password-protected Reverse TCP Shell
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---
#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have 
a close look at Linux Reverse Shells with password protection. 

A Reverse shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Bind Shell, arranging a specific connection on a trivial address, instead of binding the compromise device into a certain port. 
Furthermore, after the connection is established, a shell is executed, granting interaction to the attacker

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Reverse Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: Requires the alteration of the provided Bind Shell during the course, in order that it no longer possesses any form of NULL bytes (00). 

As exercise A is already quite a complex and long exercise, the first assignment will be segmented in two different posts, thing which may repeat within the second assignment. 
During the length of this post, you will observe the solution for exercise A.
Moreover, the main idea of a Bind Shell and process of programming such has already been explored [here](https://whitecr0wz.github.io/posts/SLAE-Bind/). Therefore, I thought of 
focusing the blog's topic on the new addition regarding the password protection instead, which is by itself rather complex. 
