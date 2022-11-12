---
layout: post
current: post
cover:  assets/buckeye/Ace314159/cover2.png
navigation: True
title: "intel does what amd'ont"
date: 2022-11-12 10:00:00
tags: [BuckeyeCTF, rev]
class: post-template
subclass: 'post'
author: Ace314159
---

This was the first time I reversed a binary with obfuscated code!

## Setup

When we run the binary, we're asked to enter a password. If we enter something random, we get an error message and the program exits:

```text
What's the password? asdf
Wrong!!!! Do better ;)
```

## When Ghidra Doesn't Work :(

As usual, I loaded the binary into Ghidra, and the decompilation kept loading for a long time. I assumed this was because of some obfuscation, making it hard for Ghidra to generate the decompilation. As a result, I started looking at the assembly. I saw that it would essentially do a "real" instruction before immediately jumping somewhere else, where it would repeat. The structure looked something like this:

![Assembly structure from Ghidra](/assets/buckeye/Ace314159/2022-11-11-23-55-30.png)

Since the obfuscation follows a pattern, I wrote a script using [Capstone](https://www.capstone-engine.org/), a disassembler, to extract the function code:

```python
from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_64)

with open("chall", "rb") as f:
    code = f.read()

addr = 0x125E

parsed = b""

try:
    while True:
        chunk = code[addr:addr + 30]
        done = False
        for i in md.disasm(chunk, addr):
            if i.mnemonic == "popfq":
                addr += i.size
                continue
            if i.mnemonic == "pushfq":
                addr += i.size
                done = True
                continue
            if done:
                if i.mnemonic == "je":
                    addr = int(i.op_str, 16)
                    break
            else:
                parsed += i.bytes
                print(f"0x{i.address}:\t{i.mnemonic}\t{i.op_str}")
            addr += i.size
except KeyboardInterrupt:
    pass


with open("parsed.bin", "wb") as f:
    f.write(parsed)
```

## Getting Ghidra to Cooperate

Then, I opened the generated binary in Ghidra. I had to clean up the assembly because Ghidra didn't give a good decompilation at first. Eventually, I ended up with this. The string begins at `start[-0xc]` because I couldn't get the function parameter to be located at an offset of `RBP`, instead of just `RBP`.

![Ghidra disassembly of generated binary](/assets/buckeye/Ace314159/2022-11-12-01-26-52.png)

It interprets the character array as an array of 32-bit unsigned integers and applies a combination of logical and arithmetic operations to each element. In the end, it compares the result to a fixed constant on the stack. I was able to figure this out by using GDB and the original code's disassembly.

![Ghidra decomplication of first comparison](/assets/buckeye/Ace314159/2022-11-12-01-18-52.png)

Ghidra's decompilation still wasn't perfect since it only showed the first comparison. I guessed that there were more because I saw 6 other constants being set in the same area of the parsed disassembly. Note that the offsets in the screenshot below are byte offsets, but the offsets in the Ghidra screenshots are 32-bit word offsets.

![Constants in disassembly](/assets/buckeye/Ace314159/2022-11-12-01-37-28.png)

## Getting the Flag

At first, I tried to use Z3 to determine what the original integer values were, but it was unable to find a solution. Then, I just chose to bruteforce all 7 values since they were each just 32-bit integers. Below is the C++ code I wrote to apply the operations, which I used in my brute-force code.

```cpp
uint32_t calcC(uint32_t start_0xc) {
    start_0xc = start_0xc << 0x18 |  start_0xc >> 0x18 | start_0xc >> 8 & 0xff00 | (start_0xc & 0xff00) << 8;
    start_0xc = start_0xc << 0x18 |  start_0xc >> 0x18 | start_0xc >> 8 & 0xff00 | (start_0xc & 0xff00) << 8;
    start_0xc = start_0xc << 0x18 |  start_0xc >> 0x18 | start_0xc >> 8 & 0xff00 | (start_0xc & 0xff00) << 8;
    start_0xc = start_0xc >> 0xc | start_0xc << 0x14;
    start_0xc = start_0xc + 0xddf10b94;
    start_0xc = start_0xc + 0x18751477;
    start_0xc = start_0xc << 0x18 |  start_0xc >> 0x18 | start_0xc >> 8 & 0xff00 | (start_0xc & 0xff00) << 8;
    start_0xc = start_0xc << 0xf | start_0xc >> 0x11;
    start_0xc = start_0xc << 0x18 |  start_0xc >> 0x18 | start_0xc >> 8 & 0xff00 | (start_0xc & 0xff00) << 8;
    start_0xc = start_0xc << 10 | start_0xc >> 0x16;
    start_0xc = start_0xc + 0x1d14bec;
    start_0xc = start_0xc << 0x18 |  start_0xc >> 0x18 | start_0xc >> 8 & 0xff00 | (start_0xc & 0xff00) << 8;
    start_0xc = start_0xc + 0x1eaa438c;
    start_0xc = start_0xc << 3 | start_0xc >> 0x1d;
    start_0xc = start_0xc >> 0xf | start_0xc << 0x11;
    start_0xc = start_0xc ^ 0xc107fdff;
    return start_0xc;
}

uint32_t calcB(uint32_t start_0xb) {
    start_0xb = start_0xb + 0x1cc9fc4c;
    start_0xb = start_0xb << 0x18 |  start_0xb >> 0x18 | start_0xb >> 8 & 0xff00 | (start_0xb & 0xff00) << 8;
    start_0xb = start_0xb + 0xc34b3165;
    start_0xb = start_0xb >> 4 | start_0xb << 0x1c;
    start_0xb = start_0xb ^ 0xa51808bd;
    start_0xb = start_0xb << 0x18 |  start_0xb >> 0x18 | start_0xb >> 8 & 0xff00 | (start_0xb & 0xff00) << 8;
    start_0xb = start_0xb >> 4 | start_0xb << 0x1c;
    start_0xb = start_0xb ^ 0xa74875c8;
    start_0xb = start_0xb + 0xbc6d6a9c;
    start_0xb = start_0xb + 0x60a2e60a;
    start_0xb = start_0xb ^ 0xfe757a16;
    start_0xb = start_0xb << 0x18 |  start_0xb >> 0x18 | start_0xb >> 8 & 0xff00 | (start_0xb & 0xff00) << 8;
    start_0xb = start_0xb >> 7 | start_0xb << 0x19;
    start_0xb = start_0xb + 0xd6941704;
    start_0xb = start_0xb << 0x18 |  start_0xb >> 0x18 | start_0xb >> 8 & 0xff00 | (start_0xb & 0xff00) << 8;
    start_0xb = start_0xb >> 3 | start_0xb << 0x1d;
    return start_0xb;
}

uint32_t calc10(uint32_t start_10) {
    start_10 = start_10 << 0x18 | start_10 >> 0x18 | start_10 >> 8 & 0xff00 | (start_10 & 0xff00) << 8;
    start_10 = start_10 << 0x18 | start_10 >> 0x18 | start_10 >> 8 & 0xff00 | (start_10 & 0xff00) << 8;
    start_10 = start_10 + 0x81980031;
    start_10 = start_10 << 0x10 | start_10 >> 0x10;
    start_10 = start_10 << 0xf | start_10 >> 0x11;
    start_10 = start_10 << 0x18 | start_10 >> 0x18 | start_10 >> 8 & 0xff00 | (start_10 & 0xff00) << 8;
    start_10 = start_10 << 0x18 | start_10 >> 0x18 | start_10 >> 8 & 0xff00 | (start_10 & 0xff00) << 8;
    start_10 = start_10 ^ 0x38593377;
    start_10 = start_10 ^ 0xddcbfa6b;
    start_10 = start_10 + 0x8ac72e2b;
    start_10 = start_10 + 0x52d7a5cd;
    start_10 = start_10 + 0xafdbff0e;
    start_10 = start_10 ^ 0x87525315;
    start_10 = start_10 + 0x3cda1555;
    start_10 = start_10 ^ 0x9c603a72;
    start_10 = start_10 << 0x18 | start_10 >> 0x18 | start_10 >> 8 & 0xff00 | (start_10 & 0xff00) << 8;
    return start_10;
}

uint32_t calc9(uint32_t start_9) {
    start_9 = start_9 << 0x18 | start_9 >> 0x18 | start_9 >> 8 & 0xff00 | (start_9 & 0xff00) << 8;
    start_9 = start_9 ^ 0xd22a4dbf;
    start_9 = start_9 << 0x18 | start_9 >> 0x18 | start_9 >> 8 & 0xff00 | (start_9 & 0xff00) << 8;
    start_9 = start_9 ^ 0xe3141dc5;
    start_9 = start_9 << 0x18 | start_9 >> 0x18 | start_9 >> 8 & 0xff00 | (start_9 & 0xff00) << 8;
    start_9 = start_9 << 0x18 | start_9 >> 0x18 | start_9 >> 8 & 0xff00 | (start_9 & 0xff00) << 8;
    start_9 = start_9 << 2 | start_9 >> 0x1e;
    start_9 = start_9 >> 0xf | start_9 << 0x11;
    start_9 = start_9 ^ 0x6f5edfd2;
    start_9 = start_9 << 0x18 | start_9 >> 0x18 | start_9 >> 8 & 0xff00 | (start_9 & 0xff00) << 8;
    start_9 = start_9 >> 8 | start_9 << 0x18;
    start_9 = start_9 + 0xc898f93c;
    start_9 = start_9 ^ 0xde730880;
    start_9 = start_9 ^ 0xfddb1cc7;
    start_9 = start_9 ^ 0x1dd5abf;
    start_9 = start_9 + 0xe5e1bf17;
    return start_9;
}

uint32_t calc8(uint32_t start_8) {
    start_8 = start_8 >> 0xf | start_8 << 0x11;
    start_8 = start_8 << 0x18 | start_8 >> 0x18 | start_8 >> 8 & 0xff00 | (start_8 & 0xff00) << 8;
    start_8 = start_8 + 0x3b746424;
    start_8 = start_8 << 0x18 | start_8 >> 0x18 | start_8 >> 8 & 0xff00 | (start_8 & 0xff00) << 8;
    start_8 = start_8 ^ 0x2440e868;
    start_8 = start_8 + 0xcbfd396d;
    start_8 = start_8 + 0x9514c01f;
    start_8 = start_8 ^ 0x2d350399;
    start_8 = start_8 ^ 0xbc3e67b0;
    start_8 = start_8 << 0x18 | start_8 >> 0x18 | start_8 >> 8 & 0xff00 | (start_8 & 0xff00) << 8;
    start_8 = start_8 + 0x6c4fef8d;
    start_8 = start_8 + 0x309e2c65;
    start_8 = start_8 << 0x18 | start_8 >> 0x18 | start_8 >> 8 & 0xff00 | (start_8 & 0xff00) << 8;
    start_8 = start_8 << 0x18 | start_8 >> 0x18 | start_8 >> 8 & 0xff00 | (start_8 & 0xff00) << 8;
    start_8 = start_8 ^ 0xdfb63420;
    start_8 = start_8 ^ 0xb7f47b56;
    return start_8;
}

uint32_t calc7(uint32_t start_7) {
    start_7 = start_7 + 0xadea03d0;
    start_7 = start_7 + 0x63fef708;
    start_7 = start_7 ^ 0x22e968a8;
    start_7 = start_7 << 0x18 | start_7 >> 0x18 | start_7 >> 8 & 0xff00 | (start_7 & 0xff00) << 8;
    start_7 = start_7 + 0xba70d62d;
    start_7 = start_7 + 0xe62a5b0b;
    start_7 = start_7 >> 2 | start_7 << 0x1e;
    start_7 = start_7 ^ 0x60362ee5;
    start_7 = start_7 << 0x18 | start_7 >> 0x18 | start_7 >> 8 & 0xff00 | (start_7 & 0xff00) << 8;
    start_7 = start_7 << 0x18 | start_7 >> 0x18 | start_7 >> 8 & 0xff00 | (start_7 & 0xff00) << 8;
    start_7 = start_7 ^ 0x800b5d0c;
    start_7 = start_7 << 6 | start_7 >> 0x1a;
    start_7 = start_7 << 0x18 | start_7 >> 0x18 | start_7 >> 8 & 0xff00 | (start_7 & 0xff00) << 8;
    start_7 = start_7 << 0x18 | start_7 >> 0x18 | start_7 >> 8 & 0xff00 | (start_7 & 0xff00) << 8;
    start_7 = start_7 >> 0xe | start_7 << 0x12;
    return start_7;
}

uint32_t calc6(uint32_t start_6) {
    start_6 = start_6 << 0x18 | start_6 >> 0x18 | start_6 >> 8 & 0xff00 | (start_6 & 0xff00) << 8;
    start_6 = start_6 ^ 0xf858bdff;
    start_6 = start_6 ^ 0x363adbe8;
    start_6 = start_6 >> 0xd | start_6 << 0x13;
    start_6 = start_6 ^ 0x15a681b3;
    start_6 = start_6 ^ 0x85a2beb9;
    start_6 = start_6 << 0x18 | start_6 >> 0x18 | start_6 >> 8 & 0xff00 | (start_6 & 0xff00) << 8;
    start_6 = start_6 << 0x18 | start_6 >> 0x18 | start_6 >> 8 & 0xff00 | (start_6 & 0xff00) << 8;
    start_6 = start_6 << 0x18 | start_6 >> 0x18 | start_6 >> 8 & 0xff00 | (start_6 & 0xff00) << 8;
    start_6 = start_6 ^ 0xaa0186d6;
    start_6 = start_6 >> 0xd | start_6 << 0x13;
    start_6 = start_6 + 0x7019d298;
    start_6 = start_6 ^ 0xd91c6bae;
    start_6 = start_6 >> 4 | start_6 << 0x1c;
    start_6 = start_6 ^ 0x1ed396a8;
    start_6 = start_6 + 0x13d34844;
    return start_6;
}
```

After a couple of minutes, I got the flag: `buckeye{w0rk5_0n_my_m4ch1n3}`

## Notes

Our team didn't solve this challenge because we ran out of time ☹️ I chose to finish solving it since I was so close. Also, the order of the sections is slightly different from the way I actually solved the challenge. I didn't realize there were more comparisons in the 32-bit array until I had brute-forced the first integer. I realized I bruteforced the string `buck`, which made me realize that the password is the flag. Then, I looked at the parsed disassembly and figured out that there were 6 more constants being set on the stack, and hoped that they corresponded to the other entries of the array -- and they did!
