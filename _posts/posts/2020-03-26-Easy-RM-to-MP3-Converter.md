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
