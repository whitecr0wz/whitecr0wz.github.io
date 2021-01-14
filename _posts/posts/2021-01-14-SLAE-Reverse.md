layout: post
title: Reverse TCP Shell 
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---
#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at Linux Reverse Shells. 

A Reverse shell is a form of malware which grants remote access to a system through a shell. However, differentiating from its peer the Bind shell, arranging a specific connection on a trivial address, instead of binding to a local port of the compromised system.

The first assignment from the seven requires the creation of a Bind Shell through the Assembly language, and afterwards, a wrapper written in any language that is capable of 
easily configuring the port.

#### Theory 

In order to create a Reverse Shellcode, 4 main functions are required:

+ Socket

+ Dup2

+ Connect

+ Execve
