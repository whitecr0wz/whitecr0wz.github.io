---
layout: post
title: Audio Playback Recorder 3.2.2 - Local Buffer Overflow (SEH)
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

#### Audio Playback Recorder 3.2.2 suffers from a Structured Exception Handling Overwrite when a long string is parsed through the parameter “License Name” within the registration in the bootup.

##### Initial PoC:

```terma
import struct

buffer = "A" * 500

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

##### Once the exploit is run, the payload is copied into the clipboard.

##### In order to exploit the application, press "Go".

![](/assets/img/Findings11/1.png)

##### Press on the button "Register".

![](/assets/img/Findings11/2.png)

##### Paste the contents of the payload on the parameter "Name".

![](/assets/img/Findings11/3.png)

###### Response of the SEH Chain.

![](/assets/img/Findings11/4.png)



![](/assets/img/Findings11/5.png)

![](/assets/img/Findings11/6.png)

![](/assets/img/Findings11/7.png)

![](/assets/img/Findings11/28.png)


![](/assets/img/Findings11/11-proof.gif)
