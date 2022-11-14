---
layout: post
current: post
cover: assets/buckeye/clash/cover.png
navigation: True
title: "powerball"
date: 2022-11-13 10:00:00
tags: [BuckeyeCTF, crypto]
class: post-template
subclass: 'post'
author: clash
mathjax: true
---

I like free money. Crypto and lottery in the same sentence? Say less.

## The Challenge
> What could go wrong using a Linear Congruential Generator to get some random numbers?

We also get a link to a website that has the current Powerball numbers, and then some blanks:

![](https://i.imgur.com/Pe7NOfJ.png)


Every minute, the numbers on the website change. 

So although I didn't really know what an LCG was (getting to that in a second), it was fairly obvious based on the style of the challenge that we need to use the current Powerball numbers to predict the next generated numbers.

## What's a Linear Congruential Generator?

Quick detour to recap the Wikipedia page about LCGs. They're a very simple type of pseudo-random number generators which start off with a seed value (let's call it $$S_0$$). Given that, $$S_n = ((a * S_{n - 1}) + b) \% c$$ for some chosen numbers a, b, c. So, multiply, add, and take the modulus to get the next number -- doesn't seem terrible at all!

## What next?

The interesting thing about this that gave me conviction that we could solve this challenge is that it got first blooded really fast! (Shoutout bluehens)

So then, I figured there was probably code out there already that helps us reverse LCGs because that's the only way they did it this fast. OSINT time??

I googled something like "lcg crypto predict next number ctf", and found this [writeup](https://ctftime.org/writeup/23246) that has this:

> After some research, I found an [awesome website](https://tailcall.net/blog/cracking-randomness-lcgs/) that explains how to crack the LCG!!

Now, that "awesome website" probably holds the ancient wisdom we're looking for -- but clicking on it returns a 404 not found. Wayback Machine to the rescue; I find the content. In fact, it turns out the content had just been moved to this URL: <https://tailcall.net/posts/cracking-rngs-lcgs/> that talks about cracking LCGs given different amounts of info, e.g. just missing the increment, or missing both multiplier and increment or missing everything. Definitely worth a read to learn some actual math.

And now, a quick detour into cracking LCGs:

## Cracking LCGs

This is the section that makes me feel better about learning something as opposed to finding a script online and running it to get the flag.

The hardest number to figure out is the modulus, so the crux of finding it comes down to this number theory trick that I learned from the article: for some random multiples of some number (our modulus), their gcd ends up being the number. 

So if we have `y = (ax + b) % c`, then `y - (ax + b) = c * n` for some random n. So if we have enough of these and we take the gcd, we find the modulus!

However, I actually forgot something very obvious up until this point: we were actually given the source code 🤦🏻‍♂️ I was just flying blind so far, not even having looked at the code.

Here are the interesting parts:

```js
function nextRandomNumber () {
    return (multiplier * seed) % modulus
}

function seedToBalls (n) {
    const balls = []
    for (let i = 0; i < 10; i++) {
        balls.push(Number(n % 100n))
        n = n / 100n
    }
    return balls
}

const modulus = crypto.generatePrimeSync(128, { safe: true, bigint: true })
const multiplier = (2n ** 127n) - 1n
let seed = 2n
for (let i = 0; i < 1024; i++) {
    seed = nextRandomNumber()
}
let winningBalls = seedToBalls(seed)
let lastLotteryTime = Date.now()

setInterval(() => {
    seed = nextRandomNumber()
    winningBalls = seedToBalls(seed)
    lastLotteryTime = Date.now()
}, 60 * 1000)
```

So the modulus is a random prime number, we're given the multiplier, and there is no increment!

With that, I made adjustments to the code from the article to get this script:

```py
from math import gcd
from functools import reduce

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

def crack_unknown_multiplier(states, modulus):
    multiplier = (2 ** 127) - 1
    return crack_unknown_increment(states, modulus, multiplier)


def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0] * multiplier) % modulus
    return modulus, multiplier, increment


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n
```

But, it looks like the values generated are actually the last 20 digits of the random number, if you take a look at the `seedToBalls` function. So, we somehow need to figure out what the actual number was so we can predict the next one.

Thankfully, checking the console yielded the full number as it changed.

![console output showing ](https://i.imgur.com/LBdKxAH.png)

Now, we have all our ingredients, so my teammate [Sam Alws](https://squ1rrel.dev/author/samalws/) and I waited 6 minutes to gather 6 different numbers, and ran the script!

```py
print(crack_unknown_modulus([
    99117384024240377377621286518682883084, 
    73700814013160696448277687043996559380, 
    35237085169882899901216316531522765344, 
    83835199739246784386479792644967600378, 
    212313483794030090215350768796417526765, 
    51629908262935582199783388296261363151
    ]))
```

And I got `(271725303640457487194263865268491373983, 170141183460469231731687303715884105727, 0)`, which gives us the modulus, multiplier and the increment.

From here, it was trivial to get the next number: we simply multiplied the last generated number and took the modulus. Then, we used the `seedToBalls()` function in the console to make it give us the balls to input.

Funnily enough, it didn't give the correct answer for me, but gave the correct one for Sam. Turns out I had swapped the multiplier and modulus while generating the next number.

We got the flag in the next console log: `buckeye{y3ah_m4yb3_u51nG_A_l1N34r_c0nGru3Nt1al_
G3n3r4t0r_f0r_P0w3rB4lL_wA5nt_tH3_b3st_1d3A}`.