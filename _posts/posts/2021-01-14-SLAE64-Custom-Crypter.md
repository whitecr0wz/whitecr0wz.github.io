---
layout: post
title: Custom Crypter
date: 2021-01-17 20:30:00
categories: posts
comments: false
en: true
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. 

According to wikipedia, "In cryptography, encryption is the process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information. Encryption does not itself prevent interference but denies the intelligible content to a would-be interceptor."

Today we are going to dive a little deep within Custom Encryption.

The last assignment from the seven requires the creation of a Custom Encrypter, written in any language that can encrypt and decrypt shellcode.

#### Theory
During the length of this post, the encryption schema employed will be [DES3](https://en.wikipedia.org/wiki/Triple_DES). Moreover, the language implemented shall be Python, with the use of the library pycrypto. In addition, I have decided to combine both the encrypter and decrypter in the same file, as a form of exercise.
Moreover, the script does not hardcode the private key, IV key nor shellcode! Making it quite dynamic.

##### The Crypter

```term
# Author: SLAE64-27812 (Felipe Winsnes)

from Crypto.Cipher import DES3
import sys


def encrypt():

            obj = DES3.new(sys.argv[2], DES3.MODE_CBC, sys.argv[3])
            message = sys.stdin.read()
            ciphertext = obj.encrypt(message)
            crypted = ""

            for x in bytearray(ciphertext):
                           crypted += '\\x'
                           ciphertext = '%02x' % x
                           crypted += ciphertext

            print '"' + crypted + '"'

def decrypt():

            obj = DES3.new(sys.argv[2], DES3.MODE_CBC, sys.argv[3])
            message = sys.stdin.read()
            decrypt = obj.decrypt(message)
            decrypted = ""

            print "Original shellcode in hex escape sequence:"

            for x in bytearray(decrypt):

                           decrypted += '\\x'
                           decrypt = '%02x' % x
                           decrypted += decrypt

            print '"' + (decrypted) + '"'

if len(sys.argv) != 4:

   print "[*] Example: echo -ne <shellcode between quotes> | python " + sys.argv[0] + " --encrypt <key> <IV number>"
   print "[*] Example: echo -ne <shellcode between quotes> | python " + sys.argv[0] + " --decrypt <key> <IV number>" + "\r\n"

   sys.exit(1)

if sys.argv[1] == "--encrypt":

      encrypt()
      sys.exit(1)

if sys.argv[1] == "--decrypt":

      decrypt()
      sys.exit(1)
```
