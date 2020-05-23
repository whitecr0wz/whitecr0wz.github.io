---
layout: post
title: Alignment on Windows Registers
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# Preamble

Welcome once again to my website! Within this post, i will be introducing methods to align x86 registers on Windows, topic that was hard for me to find when starting regarding Binary Exploitation.

## Small requirements

Despite the fact that these techniques do not require much knowledge, having beginner/intermediate experience with Assembly may help.

# Explanation of the concept

The definition of the word "alignment" is "arrangement in a straight line or in correct relative positions.", meaning that, when applied 
to CPU registers, it would refer to having two variables with the same value. 

# Why Aligning registers?

In order to execute shellcode within an stack, the payload will have to work directly with a register pointing to its address. For example, metasploit includes 6 additional bytes within all generated payloads, whose function is to align a register, so the rest can work with such. However, not all softwares may accept characters, issue which brings us to this post!
