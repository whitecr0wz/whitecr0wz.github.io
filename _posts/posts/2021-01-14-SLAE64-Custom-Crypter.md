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

According to wikipedia, "In cryptography, encryption is the process of encoding information. This process converts the original representation of the information, known as 
plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information. 
Encryption does not itself prevent interference but denies the intelligible content to a would-be interceptor."

Today we are going to dive a little deep within Custom Encryption.

The last assignment from the seven requires the creation of a Custom Encrypter, written in any language that can encrypt and decrypt shellcode.

#### Theory
During the length of this post, the encryption schema employed will be [DES3](https://en.wikipedia.org/wiki/Triple_DES). Moreover, the language implemented shall be Python, with 
the use of the library pycrypto. In addition, I have decided to combine both the encrypter and decrypter in the same file, as a form of exercise.
Even more so, the script does not hardcode the key, Initialization Vector (IV) nor shellcode! Making it quite dynamic.

Finally, the crypter requires that the shellcode is a multiple of 8, therefore, in order to not harm the execution, a few NOPs are parsed.

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


            print ' '
            print 'Encrypted shellcode in hex escape sequence:'
            print '"' + crypted + '"'

def decrypt():

            obj = DES3.new(sys.argv[2], DES3.MODE_CBC, sys.argv[3])
            message = sys.stdin.read()
            decrypt = obj.decrypt(message)
            decrypted = ""

            for x in bytearray(decrypt):

                           decrypted += '\\x'
                           decrypt = '%02x' % x
                           decrypted += decrypt

            print ' '
            print 'Original shellcode in hex escape sequence:'
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

##### Encryption

In order to test the aforementioned tool, a simple ```/bin/sh exceve``` shellcode will be employed. Furthermore, the key may be ```scvr3BbPZ9cQ2ETYG5H2qYar```, with the IV being  ```67sACHcv```.

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$ python crypter.py 
[*] Example: echo -ne <shellcode between quotes> | python crypter.py --encrypt <key> <IV number>
[*] Example: echo -ne <shellcode between quotes> | python crypter.py --decrypt <key> <IV number>

whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$ echo -ne 
"\x48\x31\xc0\x48\x31\xf6\x48\x31\xdb\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x90\x90\x90\x90" 
| python crypter.py --encrypt scvr3BbPZ9cQ2ETYG5H2qYar 67sACHcv 
 
Encrypted shellcode in hex escape sequence:
"\x57\x65\xc2\x9e\x96\x68\x5a\x91\xca\xb4\x78\xb3\xde\xe5\x8b\x35\xab\x62\xf1\xb1\x47\x22\x07\x01\xc8\x28\x91\x3e\xd5\x44\xbe\x72\x14\x53\xec\xd5\x8e\xdb\x8c\xc3"
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$
```

##### Decryption

The process of decryption is quite simple.

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$ python crypter.py 
[*] Example: echo -ne <shellcode between quotes> | python crypter.py --encrypt <key> <IV number>
[*] Example: echo -ne <shellcode between quotes> | python crypter.py --decrypt <key> <IV number>

whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$ echo -ne 
"\x57\x65\xc2\x9e\x96\x68\x5a\x91\xca\xb4\x78\xb3\xde\xe5\x8b\x35\xab\x62\xf1\xb1\x47\x22\x07\x01\xc8\x28\x91\x3e\xd5\x44\xbe\x72\x14\x53\xec\xd5\x8e\xdb\x8c\xc3" 
| python crypter.py --decrypt scvr3BbPZ9cQ2ETYG5H2qYar 67sACHcv 
 
Original shellcode in hex escape sequence:
"\x48\x31\xc0\x48\x31\xf6\x48\x31\xdb\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x90\x90\x90\x90"
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$
```

###### C format

```term
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x31\xf6\x48\x31\xdb\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x90\x90\x90\x90"

;

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

#### EndGame

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$ gcc decrypted_shellcode.c -o decrypted_shellcode -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_7$ ./decrypted_shellcode 
Shellcode Length:  40
$
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/).

Student ID: SLAE64-27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_7).
