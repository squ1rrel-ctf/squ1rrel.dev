---
layout: post
current: post
cover: assets/buckeye/bunnyrabbit022/cover.png
navigation: True
title: "bonce"
date: 2022-11-14 10:00:00
tags: [BuckeyeCTF, crypto]
class: post-template
subclass: 'post'
author: bunnyrabbit022
---

This challenge gives us two files, `output.txt` and `bonce.py`. Opening up `output.txt`, we see:

```
input: Look in thy glass, and tell 
output: 124 95 95 91 16 89 94 16 68 88 73 16 87 92 81 67 67 28 16 81 94 84 16 68 85 92 92 16 
input: the face thou viewestNow is 
output: 69 89 84 17 87 80 82 84 17 69 89 94 68 17 71 88 84 70 84 66 69 127 94 70 17 88 66 17 
input: the time that face should fo
output: 70 90 87 18 70 91 95 87 18 70 90 83 70 18 84 83 81 87 18 65 90 93 71 94 86 18 84 93 
input: rm another;Whose fresh repai
output: 65 94 19 82 93 92 71 91 86 65 8 100 91 92 64 86 19 85 65 86 64 91 19 65 86 67 82 90 


input: ???
output: 70 20 93 82 20 90 91 67 20 64 92 91 65 20 90 91 64 20 70 81 90 81 67 81 71 64 24 96 
input: ???
output: 93 90 64 21 81 90 70 65 21 87 80 82 64 92 89 80 21 65 93 80 21 66 90 71 89 81 25 21 
input: ???
output: 67 88 84 90 83 69 69 22 69 89 91 83 22 91 89 66 94 83 68 24 112 89 68 22 65 94 83 68 
input: ???
output: 82 23 94 68 23 68 95 82 23 68 88 23 81 86 94 69 23 64 95 88 68 82 23 66 89 82 86 69 
input: ???
output: 218 8340 8474 92 24 79 87 85 90 124 81 75 92 89 81 86 75 24 76 80 93 24 76 81 84 84 89 95 
input: ???
output: 92 25 86 95 25 77 81 64 25 81 76 74 91 88 87 93 75 64 6 118 75 25 78 81 86 25 80 74 
...
```

The first four lines show us an example encryption of a poem, and the rest of the file contains unknown encrypted text. No leads from just the output file, so we turn to `bonce.py`, which shows us how the inputs were encrypted:

```py
import random

with open('sample.txt') as file:
    line = file.read()

with open('flag.txt') as file:
    flag = file.read()

samples = [line[i:i+28] for i in range(0, len(line) - 1 - 28, 28)]

samples.insert(random.randint(0, len(samples) - 1), flag)

i = 0
while len(samples) < 40:
    samples.append(samples[len(samples) - i - 2])
    i = random.randint(0, len(samples) - 1)

encrypted = []
for i in range(len(samples)):
    x = samples[i]
    if i < 10:
        nonce = str(i) * 28
    else:
        nonce = str(i) * 14
    encrypted.append(''.join(str(ord(a) ^ ord(b)) + ' ' for a,b in zip(x, nonce)))

with open('output.txt', 'w') as file:
    for i in range(0, 4):
        file.write('input: ' + samples[i] + '\noutput: ' + encrypted[i] + '\n')
    file.write('\n')
    for i in range(4, len(samples)):
        file.write('\ninput: ???\n' + 'output: ' + encrypted[i])

```

The key line in this code is:

```py
samples.insert(random.randint(0, len(samples) - 1), flag)
```

It looks like the flag is randomly inserted into a line of the sample text, which I’m assuming is a nod to the challenge’s name and description, nonce (but that isn’t exactly relevant to the solution).

Reading the rest of the code, we see that every line of `output.txt` is XORed with the line number that it's on. There are some odd four digit numbers which we did not understand, so, clearly, the best solution was to ignore them. For example:

![four digit numbers in output](/assets/bluehens/bunnyrabbit022/image5.png)

At this point, we knew that the solution was to XOR every line of the output with its line number (with 0 based indexing), since XOR is symmetric, so XORing with the same key gives us the original input. However, in the spirit of ignoring things I don’t understand, I decide to do it semi-by-hand, while skipping the strange lines and hoping things go well.

Whipping up this recipe in CyberChef, I confirmed the decryption with the first line, and it looks like it goes well:

![example cyberchef xor output](/assets/bluehens/bunnyrabbit022/image1.png)

From here, I proceeded to go through all the reasonable looking lines of the output. Eventually, I got to line 19, and we got the flag!

![cyberchef xor output with flag](/assets/bluehens/bunnyrabbit022/image4.png)

`buckeye{some_say_somefish:)}`