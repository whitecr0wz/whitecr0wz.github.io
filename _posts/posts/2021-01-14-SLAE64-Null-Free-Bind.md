---
layout: post
title: Null-free Bind Shell
date: 2021-01-19 20:30:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification.

A Bind shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Reverse Shell, binding to a local port of 
the compromised system, instead of arranging a specific connection on a trivial address. Furthermore, after the connection is established, a shell is executed, granting 
interaction to the attacker.

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Bind Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: The discussed Bind Shell provided during the course should be modified, in order that it no longer possesses any form of NULL bytes (00). 

As in the [previous](https://whitecr0wz.github.io/posts/SLAE64-Bind-Password/) post exercise A was tackled, this post will be focused towards the seconodary task.

Let's analyze the Bind Shell given 
