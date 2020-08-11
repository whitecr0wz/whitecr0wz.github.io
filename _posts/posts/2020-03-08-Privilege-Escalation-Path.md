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

### As the reader may already know, in Linux the $PATH is an environmental variable which allows the system to search for an executable on specific folders. For example, if i want to execute "ls", i don't have to resort to the full path, being /bin/ls, as it is already within the $PATH. However, there are binaries which sometimes do not use the full path and make use of such variable, that if maliciously manipulated, the file which is intended to run may be "hijacked", I.E: FTP server which makes a call to telnet without the full path, if the variable was changed to only "/tmp", telnet would only be searched for in such folder, ergo, if a file is placed there with the same name, it would get executed.

# The Exploitation

### In order to demonstrate this phenomenon, a vulnerable application will be used.

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

#### It is copied to /usr/bin/vuln, chmoded with user bits and finally checked:

```term
root@whitecr0wz:~/vuln# cp vuln /usr/bin/vuln
root@whitecr0wz:~/vuln# chmod u+s /usr/bin/vuln
root@whitecr0wz:~/vuln# ls -la /usr/bin/vuln 
-rwsr-xr-x 1 root root 16712 Aug 10 19:58 /usr/bin/vuln
root@whitecr0wz:~/vuln# 
```
