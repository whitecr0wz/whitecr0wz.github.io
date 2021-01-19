---
layout: post
title: Custom Encrypter
date: 2021-01-19 20:30:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. 

According to wikipedia, "In cryptography, encryption is the process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information. Encryption does not itself prevent interference but denies the intelligible content to a would-be interceptor."

Today we are going to dive a little deep within Custom Encryption. 

The last assignment from the seven requires the creation of a Custom Encrypter, written in any language that can encrypt and decrypt shellcode. In addition, the decrypter should execute the shellcode.

#### Theory

During the length of this post, the crypter used will be Blowfish. Moreover, the language employed will be Python, with the use of the library [pycrypto](https://pypi.org/project/pycrypto/)
