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
