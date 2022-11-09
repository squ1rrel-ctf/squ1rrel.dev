---
layout: post
current: post
cover: assets/bluehens/cryptoduck/cover.png
navigation: True
title: "CryptoDuck!"
date: 2022-11-04 10:00:00
tags: [BlueHensCTF, misc]
class: post-template
subclass: 'post'
author: squ1rrel
---

Digital circuits and Python: low-level meets high-level in the solution to this oddball of a challenge.

# Setup
We're given some text being said by a "RoboDuck":
```
Nak Nanak naknak Nananak naknaknak Nak? Nak Nanak nak. Nananak naknaknak Nak? Naknak naknak nak. Nanak naknak Naknaknaknak naknaknak Nak? Nak. Nanak Nak? Nak? naknaknak Nak? Nak Nak? Naknak Nak? nak. Nanak naknak Naknaknaknak naknak naknak naknaknak Nanak naknaknak Nanak naknaknak Nanak
```
We're also given this malicious circuit that was injected into the RoboDuck's voicebox:
![Malicious circuit](https://raw.githubusercontent.com/AndyNovo/UDCTF22/master/misc/cryptoduck/daffy_duck.png)

# Coding up the circuit
First things first, let's code up this circuit in the voicebox. We make a Python function that takes an 8-tuple of bools (A-H on the left of the circuit)
and returns another 8-tuple of bools (A-H on the right of the circuit).
```python
def voicebox(input):
  (a,b,c,d,e,f,g,h) = input
  output = (
    (not g) ^ h, # A
    f or g, # B
    f, # C
    d and (e if d else f), # D
    # d and (f if d else e), # D
    not d, # E
    not c, # F
    b and c, # G
    not (a or b) # H
  )
  return output
```

# Reversing the circuit
We're given what the RoboDuck says out loud, but what we really want is what it's *trying* to say (the flag).
We need to reverse the voicebox circuit.
We could try to reverse this circuit by hand, but there might be some outputs produced by multiple inputs,
and other outputs that can't be produced at all!
On the other hand, there are only 256 possible inputs (2^8), so we can just bruteforce it instead, with this slightly hacky bit of Python code:
```python
def voiceboxReverse(output):
  bits = [False,True]
  inputs = []
  for a in bits:
    for b in bits:
      for c in bits:
        for d in bits:
          for e in bits:
            for f in bits:
              for g in bits:
                for h in bits:
                  input = (a,b,c,d,e,f,g,h)
                  if voicebox(input) == output:
                    inputs.append(input)
  return inputs
```

# We're done! (Nope)
So, we have the output from the voicebox, and we have a function to reverse the voicebox's effect.
All we need to do is look up each output character in an ASCII table,
and we should be able to figure out what's being inputted to the voicebox, right?
```py
print(voiceboxReverse((False,True,False,False,True,True,True,False))) # 'N' = 4E in ASCII
# []
```
Wrong...

# Google saves the day
What does the modern man do when confronted with a problem like this?
Google it, of course!
A quick search for "naknak duckspeak" brings up info about a duckspeak cipher.
Each word in the duck's speech corresponds to a single hexadecimal digit:
"Nak" means 0, "Nanak" means 1, "naknak" means C, and so on for the rest of the words.
We wrote up another quick Python file to decode duckspeak to bytes:
```py
encoded = "Nak Nanak naknak [... and so on ...]"

mapping = {
    "Nak":  0,
    "Nanak":  1,
    "Nananak":  2,
    "Nanananak":  3,
    "Nak?":  4,
    "nak?":  5,
    "Naknak":  6,
    "Naknaknak":  7,
    "Nak.":  8,
    "Naknak.":  9,
    "Naknaknaknak": 10,
    "nanak": 11,
    "naknak": 12,
    "nak!": 13,
    "nak.": 14,
    "naknaknak": 15,
}

decoded = ""
for word in encoded.split(" "):
    decoded += str(hex(mapping[word]))[2:]
decoded = bytes.fromhex(decoded)

print(decoded)
```
We get `b'\x01\xc2\xf4\x01\xe2\xf4l\xe1\xca\xf4\x81D\xf4\x04d\xe1\xca\xcc\xf1\xf1\xf1'` as our output,
which we can now feed into `voiceboxReverse` (after some ASCII conversion) to get the possible inputs:
```
['1']
['s', 'ó']
['\\', '_', '\x9c', '\x9f', 'Ü', 'ß']
['1']
['t', 'w', 'ô', '÷']
['\\', '_', '\x9c', '\x9f', 'Ü', 'ß']
['E', 'F', 'M', 'N', '\x85', '\x86', '\x8d', '\x8e', 'Å', 'Æ', 'Í', 'Î']
['4', '7']
['c', 'k', 'ã', 'ë']
['\\', '_', '\x9c', '\x9f', 'Ü', 'ß']
['0']
['R', '\x92', 'Ò']
['\\', '_', '\x9c', '\x9f', 'Ü', 'ß']
['Q', '\x91', 'Ñ']
['U', 'V', '\x95', '\x96', 'Õ', 'Ö']
['4', '7']
['c', 'k', 'ã', 'ë']
['C', 'K', '\x83', '\x8b', 'Ã', 'Ë']
['<', '?']
['<', '?']
['<', '?']
```
Now all we need to do is pick one from each list to make a valid-looking flag.
After staring for a bit, we find `1s_1t_N4k_0R_QU4cK???`, which, when wrapped with `UDCTF{}`, gives us the flag!