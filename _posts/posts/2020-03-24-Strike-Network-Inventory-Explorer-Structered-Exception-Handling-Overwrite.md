---
layout: post
title: 10-Strike Network Inventory Explorer 'Add' Structered Exception Handling Overwrite
date: 2020-03-24 14:27:00
categories: posts
comments: false
en: true
---

# Preamble
Today i was gathering around Exploit-DB, when i found [this](https://www.exploit-db.com/exploits/44838) exploit, so i thought of searching a vulnerability in such software.

# The Bug
10-Strike Network Inventory Explorer suffers from a Structered Exception Handling (SEH) overwrite when issuing a long command within the 'Add' parameter, meaning that arbitrary code may be executed within a crafted exploit.

Initial PoC script:

```
import struct

buffer = "A" * 1000
f = open ("strike.txt", "w")
f.write(buffer)
f.close()
```
