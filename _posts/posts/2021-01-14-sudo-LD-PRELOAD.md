---
layout: post
title: Privilege Escalation - SUDO: 'LD_PRELOAD' Privilege Escalation
date: 2021-02-08 11:33:00
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
