---
layout: post
title: Custom Encoder
date: 2021-01-14 18:18:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. Today we are going to have a close 
look at a Custom Encoder. 


The fourth assignment from the seven requires the creation of a Custom Encoder, similar to the one shown in the course as the "Insertion Encoder". This should be written in the Assembly language, and converting such into [shellcode](https://es.wikipedia.org/wiki/Shellcode). Moreover, it is required that such is tested later on the C format.

##### The Encoder

As for the encoder itself, I have chosen to concanate the three main techniques regarding encoding during the course, therefore, the encoder obeys the following procedure:

+ XORs every opcode of the shellcode by 46.
+ Performs a NOT operation on every opcode of the shellcode.
+ Inserts an additional 0x45 byte for every opcode.
