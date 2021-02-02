---
layout: post
title: x86_64 Egghunter
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have a close 
look at Egghunters. 

An Egghunter is a form of malware, commonly used during Exploit-Development sessions in order to process bigger shellcode when there is low space available. The process is quite 
simple, this will search for a specific tag within the memory. When found, the flow will be passed upon the instructions following the tag, executing the original shellcode. 
