---
layout: post
current: post
cover: assets/htb/aeswcm/cover.webp
navigation: True
title: "AESWCM"
date: 2023-01-02 22:00:00
tags: [HTB, crypto]
class: post-template
subclass: 'post'
author: holden
mathjax: true
mermaid: true
---

Cryptography transcends wizardry.

## The Challenge
In this challenge, the user connects to the server and is prompted with the following question:
```
What properties should your magic wand have?
```
Following this, the user can input any property in hex which is then added as a characteristic for a magic wand. This is repeated three times. Should the user input repeated properties, then the program will prompt:
```
Only different properties are allowed!
```
Following this error, the prompt will exit. Here's a full example of a server interaction:
```
What properties should your magic wand have?
Property: FF
7addf85ef83df437c4f7054a1fa2f042
Property: 0F
7fefc70a079f8966b9b6c25418d9265f
Property: FF
Only different properties are allowed!
```
## Overall Program Function
In order to better understand the function of the server, it is necessary to delve into its decision-making code.
```python
def main():
    aes = AESWCM(KEY)
    tags = []
    characteristics = []
    print("What properties should your magic wand have?")
    message = "Property: "

    counter = 0
    while counter < 3:
        characteristic = bytes.fromhex(input(message))
        if characteristic not in characteristics:
            characteristics.append(characteristic)

            characteristic_tag = aes.tag(message.encode() + characteristic, IV)
            tags.append(characteristic_tag)
            print(characteristic_tag)

            if len(tags) > len(set(tags)):
                print(FLAG)

            counter += 1
        else:
            print("Only different properties are allowed!")
            exit(1)
```
The program begins as observed above, with a prompt for a magic wand characteristic. Following this, the characteristic is converted to bytes and added to a list of prior characteristics if it is unique. The characteristic is then encrypted using the provided custom `AESWCM` class and appended to a list of prior `AES` encrypted tags. The flag is revealed if the length of the tag list is greater than the length of the set of the tags list; that is, if there is a duplicate in the tag list then the flag is printed. Therefore, all that must be achieved to determine the flag is `AES` collision; however, `AES` is not a hash function and there are no collisions, so there must be some error in the provided `AESWCM` class that facilitates a collision.

## Encryption Analysis
Beginning our analysis of the `AESWCM` class, let's briefly go through `AESWCM.__init__`.
```python
    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.BLOCK_SIZE = 16
```
Within this constructor, there are three important variables created.
1. `self.key`
2. `self.cipher`
3. `self.BLOCK_SIZE`

`self.key` is aptly named because it is the key to the `AES` encryption method implemented within the `AESWCM` class. What `AES` mode is used, you might ask? Well, using my top-notch detective skills (I put the NSA to shame <sub>Hire me please</sub>) on the assignment of `self.cipher` to `AES.new(self.key, AES.MODE_ECB)` I think it is safe to say we are using `AES-ECB`, which is an insecure `AES` encryption standard that I will discuss momentarily. The final variable declared is `self.BLOCK_SIZE`, which simply designates the number of bytes per *block* for the `AES-ECB` encryption.

### A Review of AES-ECB
Let's take a brief moment to review `AES-ECB` and why it is one of the more (if not most) insecure `AES` modes. To begin, `AES-ECB` is a block cipher, meaning that it splits a plaintext into blocks of a particular number of bytes. In our case, `self.BLOCK_SIZE` is $$16$$, meaning that the plaintext encrypted will be split into blocks of size $$16$$ bytes. For instance, consider the following example:
```
pt = "000000000000000000000000000000000101010101010101010101010101010102020202020202020202020202020202"
pt_blocks = blockify(pt)
# pt_blocks = ["00000000000000000000000000000000", "01010101010101010101010101010101", "02020202020202020202020202020202"]
```
A single hex *'digit'* is $$1$$ nibble; that is, $$\frac{1}{2}$$ a byte. Therefore, a block of size $$16$$ bytes with hex would have $$32$$ hex *'digits'* as shown above. Following this split of the plaintext ( $$pt$$ ) into blocks, each block is individually encrypted using the same key in the process of standard `AES` block encryption.

<div class="mermaid">
graph TD
    classDef default fill:#0080FF,stroke:#000,color:#000
    classDef key fill:#80FF00,stroke:#000,color:#000
    classDef encryption fill:#FF8000,stroke:#000,color:#000
    classDef ct fill:#FF007F,stroke:#000,color:#000

    pt1("Plaintext Block 1")
    pt2("Plaintext Block 2")
    pt3("Plaintext Block 3")

    k1("Key"):::key
    k2("Key"):::key
    k3("Key"):::key

    e1("Block Cipher Encryption"):::encryption
    e2("Block Cipher Encryption"):::encryption
    e3("Block Cipher Encryption"):::encryption

    ct1("Ciphertext"):::ct
    ct2("Ciphertext"):::ct
    ct3("Ciphertext"):::ct

    pt1-->e1-->ct1
    pt2-->e2-->ct2
    pt3-->e3-->ct3

    k1-->e1
    k2-->e2
    k3-->e3
</div>

The issue and vulnerability in `AES-ECB` is that every single block is encrypted with the same key such that if the plaintext of one block is known, then any other reoccurrences of identical ciphertext indicate the known plaintext. Consider the following:
```python
pt_1 = "mega secret msg:"
pt_2 = "mega secret msg: do not use AES pwds"
# Omiited blocking of plaintexts 
# Ommitted encryption calls
ct_1 = "18b44cd1683cf0b227de75a43a5b2f46"
ct_2 = "18b44cd1683cf0b227de75a43a5b2f462357ff9ee5b21a1b9b2464644b094823"
# The first 16 bytes of both ciphertexts are the same because they have the same plaintext
```
This is one of the primary ways in which `AES-ECB` is vulnerable to attacks: the same plaintext will result in the same ciphertext every time. Now that `AES-ECB` has been briefly reviewed, let us move onto some `AESWCM` class functions.

### The `pad` Function
As priorly discussed, `AES-ECB` is a block cipher and encrypts blocks of a particular size (in this case $$16$$ bytes); however, what if a block has $$<16$$ bytes? Well, this is where padding comes in: it essentially adds bytes of information to the end of a block until it is the required encryption size. This particular function really just calls the padding function defined in `Crypto.Util.Padding`, so long as $$len(pt)\not\equiv0\hspace{.15cm}mod\hspace{0.15cm}self.BLOCK\_SIZE$$.
```python
    def pad(self, pt):
        if len(pt) % self.BLOCK_SIZE != 0:
            pt = pad(pt, self.BLOCK_SIZE)
        return pt
```
Here's an example output from this function
```python
pt = b'pad this'
pt_pad = pad(pt)
pt_pad = b'pad this\x08\x08\x08\x08\x08\x08\x08\x08'
```
### The `blockify` Function
The aptly named `blockify` function is quite straightforward. Essentially, it accepts a byte array `message` parameter and splits it into *blocks* with a size of `self.BLOCK_SIZE` bytes. 
```python
    def blockify(self, message):
        return [
            message[i:i + self.BLOCK_SIZE]
            for i in range(0, len(message), self.BLOCK_SIZE)
        ]
```
Here's an example output from this function:
```python
pt = b'blockify this message please and thank you :)'
pt_blocks = [b'blockify this me', b'ssage please and', b' thank you :)']
```
### The `xor` Function
The `xor` function does exactly what the name implies and xors two $$16$$ element byte arrays together. XOR is also known as the eXclusive OR (XOR) function. $$\oplus$$ is the typical math notation for xor, and ^ is the bitwise operator for xor in python. Here's its truth table:

 $$A$$ | $$B$$ | $$A\oplus B$$
:--: | :--: | :---------:
 0 | 0 | 0 
 0 | 1 | 1 
 1 | 0 | 1 
 1 | 1 | 0

Additionally, it has several useful properties:

$$\begin{align}
A\oplus 0 &= A \\
A\oplus A&=0 \\
(A\oplus B)\oplus C &= A\oplus (B\oplus C) \\
A\oplus B &= B\oplus A \\
A\oplus B&=C \Rightarrow A\oplus C = B \wedge C\oplus B = A \\
\end{align}$$

For this challenge in particular, the most important properties are $$\oplus$$'s commutativity property, and the fact that to undo a $$\oplus$$ you perform $$\oplus$$ on the result with either term (shown as the last property in the list above).

### The `encrypt` Function
Now that the `blockify`, `xor` and `pad` functions have been discussed, the main encryption function can be looked at.
```python
    def encrypt(self, pt, iv):
        pt = self.pad(pt)
        blocks = self.blockify(pt)
        xor_block = iv

        ct = []
        for block in blocks:
            ct_block = self.cipher.encrypt(self.xor(block, xor_block))
            xor_block = self.xor(block, ct_block)
            ct.append(ct_block)

        return b"".join(ct).hex()
```

The first step of the `encrypt` function is for the message to be padded and then split into blocks using the aforementioned `pad` and `blockify` functions. Thereafter, a variable named `xor_block` is set to the intermediate value ( `iv` ) which is the result of a Cryptographically Secure Psuedo-Random Number Generator (CSPRNG). Then, each `block` is $$\oplus$$ed with `xor_block` and subsequently encrypted using the `AES-ECB` object created in `AESWCM.__init__`. A very important part of this process is that `xor_block` is changed with each iteration to be the $$\oplus$$ of the created `ct_block` and `block`. This manual addition essentially turns the `AES-ECB` encryption into something similar to `AES-CBC` which we will quickly review.

### A Review of `AES-CBC`
Similarly to `AES-ECB`, `AES-CBC` is a block cipher and a provided plaintext is divided into blocks for encryption. However, unlike `AES-ECB`, each `pt` block is $$\oplus$$ed with an Intermediate Value ( `iv` ) prior to encryption. The first `iv` is a random number; however, all subsequent `iv`s are generated from the $$\oplus$$ing of the generated `ct` block with the next `pt` block. This removes one of the primary vulnerabilities of `AES-ECB`, where blocks consisting of the same plaintext receive the same ciphertext. Here is a colorful graph for you to ponder:

<div class="mermaid">
flowchart TD
    classDef default fill:#0080FF,stroke:#000,color:#000
    classDef key fill:#80FF00,stroke:#000,color:#000
    classDef encryption fill:#FF8000,stroke:#000,color:#000
    classDef ct fill:#FF007F,stroke:#000,color:#000
    classDef iv fill:#6600CC,stroke:#000,color:#000
    classDef xor fill:#FFF,stroke:#000,color:#000

    ct("Ciphertext"):::ct

    k1("Key"):::key
    k2("Key"):::key
    k3("Key"):::key

    pt1("Plaintext Block 1")
    pt2("Plaintext Block 2")
    pt3("Plaintext Block 3")

    e1("Block Cipher Encryption"):::encryption
    e2("Block Cipher Encryption"):::encryption
    e3("Block Cipher Encryption"):::encryption

    ct1("Ciphertext Block 1"):::ct
    ct2("Ciphertext Block 2"):::ct
    ct3("Ciphertext Block 3"):::ct

    xor1("⊕"):::xor
    xor2("⊕"):::xor
    xor3("⊕"):::xor

    IV-->xor1

    pt1-->xor1-->e1-->ct1-->ct
    pt2-->xor2-->e2-->ct2-->ct
    pt3-->xor3-->e3-->ct3-->ct

    ct1-->xor2
    ct2-->xor3

    k1-->e1
    k2-->e2
    k3-->e3
</div>

## Back to `encrypt`
Now, returning to the `encrypt` function, we notice a peculiarity. In typical `AES-CBC` implementations, there is not an `xor_block`, but instead the previous `ct` is $$\oplus$$ed with the current `pt` ( $$ct=IV$$ in the case of the first block). This peculiarity will be important later on. Creating a flow chart for the actual `AESWCM` process provides the following:

<div class="mermaid">
flowchart TD
    classDef default fill:#0080FF,stroke:#000,color:#000
    classDef key fill:#80FF00,stroke:#000,color:#000
    classDef encryption fill:#FF8000,stroke:#000,color:#000
    classDef ct fill:#FF007F,stroke:#000,color:#000
    classDef xor fill:#FFF,stroke:#000,color:#000
    classDef iv fill:#FFD900,stroke:#000,color:#000

    ct("Ciphertext"):::ct

    k1("Key"):::key
    k2("Key"):::key
    k3("Key"):::key

    pt1("Plaintext Block 1")
    pt2("Plaintext Block 2")
    pt3("Plaintext Block 3")

    e1("Block Cipher Encryption"):::encryption
    e2("Block Cipher Encryption"):::encryption
    e3("Block Cipher Encryption"):::encryption

    ct1("Ciphertext Block 1"):::ct
    ct2("Ciphertext Block 2"):::ct
    ct3("Ciphertext Block 3"):::ct

    xor1("⊕"):::xor
    xor2("⊕"):::xor
    xor3("⊕"):::xor

    IV("IV (xor_block)"):::iv
    IVxor2("⊕ (xor_block)"):::iv
    IVxor3("⊕ (xor_block)"):::iv

    IV-->xor1
    IVxor2-->xor2
    IVxor3-->xor3

    ct1-->IVxor2
    pt1-->IVxor2
    ct2-->IVxor3
    pt2-->IVxor3

    pt1-->xor1-->e1-->ct1-->ct
    pt2-->xor2-->e2-->ct2-->ct
    pt3-->xor3-->e3-->ct3-->ct

    k1-->e1
    k2-->e2
    k3-->e3
</div>

### `tag` Function
The final function in the `AESWCM` class, and the same function called inside `main`, is the `tag` function. This function acts as an outline for the entire creation process of a wand characteristic's tag and is incredibly important. Thankfully, it is also quite simple.

```python
    def tag(self, pt, iv=os.urandom(16)):
        blocks = self.blockify(bytes.fromhex(self.encrypt(pt, iv)))
        random.shuffle(blocks)

        ct = blocks[0]
        for i in range(1, len(blocks)):
            ct = self.xor(blocks[i], ct)

        return ct.hex()
```
A majority of the work performed by this function courts within its first line, where the encrypt function is called on the passed `pt` and subsequently split into blocks once more. These blocks are then randomly shuffled, and the first block in the `blocks` list is $$\oplus$$ed with all other blocks in `blocks` and then returned. See? It's pretty straightforward.

## The Exploit
Now that we fully understand the happenings of the script, it is time to break it and cause a collision. In order to facilitate this, let's work backwards. The tag added to list is a result of the $$\oplus$$ of all current characteristics' `ct` blocks ( $$ct_1, ct_2, ct_3, ...$$ ). (Because $$\oplus$$ is commutative the random shuffling of the blocks is of little importance.) From the $$\oplus$$ed properties above, it can be understood that for a collision to occur, the result of two `tag` calls must be the same. The simplest manner by which this can be achieved is by first passing enough plaintext for a singular block, and then somehow having the second block be a repetition of $$0$$'s; however, this becomes difficult due to the AES encryption by an unknown key. Finding the characteristic that would result in a $$0$$ block is difficult.  
  
Therefore, the next best option is for the result of a $$\oplus$$ being *'undone'* by another $$\oplus$$. This requires $$3$$ steps (which we coincidentally have).
1. Determining the ciphertext of the first block ( $$ct_1$$ ) and the next xor block ( $$xor\_block_2$$ )
2. Determining the ciphertext of the second block ( $$ct_2$$ ) and the next xor block ( $$xor\_block_3$$ )
3. Inputting a final block ( $$pt_3$$ ) that encrypts to the same as the second or first block ( $$ct_3=ct_2$$ or $$ct_3=ct_1$$ )

### Determining the Ciphertext of the First Block
Determining the ciphertext of the first block is incredibly simple. If there is only $$1$$ block and it is $$16$$ bytes, then it will simply be $$\oplus$$ed with the $$IV$$, encrypted, and then returned since there are no other blocks for it to be $$\oplus$$ed against. Therefore, whatever is returned from the tag function ( $$tag_1$$ ) is the ciphertext of the first characteristic such that $$tag_1=ct_1$$. Now, to determine $$xor\_block_2$$, think back to the peculiarily of the `AESWCM`'s `xor_block` function. $$xor\_block_2$$ can be calculated as $$xor\_block_2=ct_1\oplus pt_1$$. This will be useful for ensuring the same text is encrypted by `AES-ECB` on the second and third iterations.

### Determining the Ciphertext of the Second Block
Determining the ciphertext of the second block is similarly just as simple as with the first block; however, there are some additional steps that should be taken. First, the ciphertext of the second block can be easily found by simply $$\oplus$$ing the first ciphertext ( $$ct_1$$ ) with the second tag ( $$tag_2$$ ); $$ct_2=ct_1\oplus tag_2$$. Now that the ciphertext of the second block has been determined $$xor\_block_3$$ may be determined a la step #1 by $$xor\_block_3=ct_2\oplus pt_2$$.

### Inputting a final block that encrypts to the same as the second or first block
The final step in creating a tag collision is to ensure that the input to the `AES-ECB` encrypt is the same. This can be done due to the faulty implementation of `xor_block`. The implementation allows us to determine that $$pt_2$$ turns into $$input_2$$ per the equation $$input_2=xor\_block_2\oplus pt_2$$. In order for $$ct_2=ct_3$$ then $$input_2=input_3$$, giving:  

$$\begin{align}
input_2&=input_3 \\
xor\_block_2 \oplus pt_2 &= xor\_block_3 \oplus pt_3 \\
xor\_block_2 \oplus pt_2 \oplus xor\_block_3 &= pt_3 \\
\end{align}$$ 
  
Therefore, the plaintext for block $$3$$ ( $$pt_3$$ ) needs to be $$xor\_block_2 \oplus pt_2 \oplus xor\_block_3$$.

### Putting it All Together
Putting all of these steps together, I created the following crude and manual (don't judge me I didn't know how to use pwntools) code:
```python
message = "Property: "
def xor(a, b):
        return bytes([aa ^ bb for aa, bb in zip(a, b)])

# FIRST INPUT
# 000000000000
# SECOND INPUT
# 00000000000011111111111111111111111111111111

block1 = b'Property: \x00\x00\x00\x00\x00\x00'
block2 = b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11'

# GET TAG1 FROM THE SERVER
tag1_hex = "3ea94a73f37d7a37a195e2ed066a46e3"
tag1 = bytes.fromhex(tag1_hex)
ct1 = tag1
xor2 = xor(block1, ct1)

# GET TAG2 FROM THE SERVER
tag2_hex = "d35ee132580b4d60d860c3308379389c"
tag2 = bytes.fromhex(tag2_hex)
ct2 = xor(tag2, ct1)
xor3 = xor(block2, ct2)

ans = xor(xor(xor2, xor3), block2)
print(ans.hex())
```
Running the server in a separate terminal with the given blocks and substituing values into the script allows for the required $$pt_3$$ to be found and subsequently submitted for the flag!

## Conclusion
This was my first CTF, second challenge I had ever looked at, and first CTF challenge I feel like I solved independently (Most of this came to me in a dream during a shower). And I have to say, it was a lot of fun. I would like to say thank you to all my wonderful teammates who welcomed me into this incredible club and helped me get started on this challenge and all others; it has been great working with you all. Additionally, I would like to give thanks to HackTheBox for putting on such an amazing competition with tons of unique challenges.

<sub>If you have any comments or questions shoot me a message, thanks again for reading!</sub>
