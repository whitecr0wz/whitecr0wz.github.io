---
layout: post
title: Easy RM to MP3 Converter 2.7.3.700 - 'Input' Buffer Overflows
date: 2020-03-26 16:05:00
categories: posts
comments: false
en: true
---

# Preamble
After finishing with the [previous](https://whitecr0wz.github.io/posts/Easy-RM-to-MP3-Converter/) vulnerability, i was eager to find out if i could exploit another vulnerable function within this program, which brought us to this post.

# The Bug

Easy RM to MP3 Converter 2.7.3.700 suffers from a vulerability in which it is possible to trigger a Buffer Overflow or a Structured Exception Handling Overwrite when specifying a long string within the parameter "Input" in the "Batch" section.

A small fuzzing script is generated:

```term_session
import struct

buffer = "A" * 50000

f = open ("finding3.txt", "w")
f.write(buffer)
f.close()
```

After this script is run, its contents are copied into the clipboard with Notepad++:

![](/assets/img/Findings3/1.png)
