---
layout: post
title: Beating ASLR & NX/DEP without Additional PE Headers nor Code Caves (VOL:III)
date: 2020-03-08 18:00:00
categories: posts
comments: false
en: true
---

### Introduction

You find yourself reading the third volume of the "PE File Backdooring" series. As a result of such, I highly recommend reading the [first](https://whitecr0wz.github.io/posts/Backdooring-PE/) and [second](https://whitecr0wz.github.io/posts/Backdooring-PE-II/) blog post of the series, as it may help understanding the shown material on this post.

Today, I will be explaining how to backdoor PE Files when heavy protections such as ASLR and NX/DEP are present without altering the binary at all.
Furthermore, in order to replay the concept, the well-known [task manager](https://en.wikipedia.org/wiki/Task_Manager_(Windows)) will be employed, due to the reason that it has all protections enabled and as it is a common executable.
