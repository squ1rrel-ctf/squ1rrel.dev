---
layout: post
current: post
cover: assets/buckeye/samalws/cover.png
navigation: True
title: "SSSHIT"
date: 2022-11-13 10:00:00
tags: [BuckeyeCTF, crypto]
class: post-template
subclass: 'post'
author: samalws
mathjax: true
---

A crypto challenge that boils down to "3x - 3a + b = c".

But it's the learning experience that matters, right?

# Setup
We're given a server to `netcat` into and a Python file that runs on it.
When run, the file prints the following (numbers are different each time):
```
I wrote down a list of people who are allowed to get the flag and split it into 3 using Shamir's Secret Sharing.
Your share is:
(1, 5633848164677390252701914670965270184760026556386817744129221631450069984002678101090048130422008563266639568759746726386131543239557666026346105273360573)
The other shares are:
(2, 502884063261798815389586773696637620038871059209008024629519145962728425380056300134268799627497812437351461043167950508188126504855877169128069033172684)
(3, 299800464877178076288866740674841206004236890401149246694572902707867350793435753874417341680884649201379366366068535858800318369082674734992347926779516)

Now submit your share for reconstruction:
>>>
```

## Hold on, what's Shamir's Secret Sharing?
The first step to solving this challenge is figuring out what Shamir's Secret Sharing even is.
It turns out that it isn't too complicated.
The idea is this: we have a secret piece of data, and we want to give out "shares" of this data.
Individually, each share is useless for figuring out the secret,
but if enough shareholders tell you their shares, you can figure out the secret data.
Specifically, when we're encrypting the data and making shares, we can choose any number $$k$$ so that you need at least $$k$$ shares to get the data.
Let's take a look at the specifics of how this is implemented.

*(Note: in real implementations of Shamir's Secret Sharing, all the math is done modulo some large number.
We leave this detail out for the sake of simplicity.)*

## Encrypting the data
Let's say we want to encrypt a number a, making n shares, with k shares needed to get the data.
The first step to encrypting it is randomly generating integers $$b_1, b_2, ... b_{k-1}$$.
Then, we make a polynomial $$p(x) = a + b_1 x^1 + b_2 x^2 + ... + b_{k-1} x^{k-1}$$.
The y-intercept of this polynomial is our secret data point, so anyone who finds out the polynomial can find the secret data point.
To make shares from this polynomial, we just sample the polynomial at n different points; each $$(x,y)$$ value is a share.
We can now give away all the shares to different people.

## Decrypting the data
Now let's say we have k shares, $$(x_1, y_1)$$ through $$(x_k, y_k)$$, and we want to figure out the original secret number, $$a$$.
If we can figure out the polynomial $$p$$, then we can get its y-intercept, and we will know the secret number.
Luckily for us, there's only one possible (k-1)-dimensional polynomial going through these $$k$$ points,
and figuring it out is a solved problem, known as *polynomial interpolation*.

## Polynomial Interpolation
We want to find a (k-1)-dimensional polynomial going through $$(x_1, y_1), ..., (x_k, y_k)$$.
One way to do this is to find $$k$$ different polynomials,
each of which goes through one of the $$(x,y)$$ pairs and is 0 at all of the other $$x$$ values,
and then to add these polynomials up.
These polynomials can be given by
$$p_i(x) = y_i \frac{x-x_1}{x_i-x_1} \frac{x-x_2}{x_i-x_2} ... \frac{x-x_{i-1}}{x_i-x_{i-1}} \frac{x-x_{i+1}}{x_i-x_{i+1}} \frac{x-x_{i+2}}{x_i-x_{i+2}} ... \frac{x-x_k}{x_i-x_k}$$.
Each of the $$\frac{x-x_j}{x_i-x_j}$$ terms are 0 at $$x_j$$ and 1 at $$x_i$$,
and the $$y_i$$ is multiplied on the front to make the polynomial evaluate to $$y_i$$ at point $$x_i$$.
(These polynomials without the $$y_i$$ in front are known as *Lagrange basis polynomials*).

Finally we have an answer for what p is: $$p(x) = p_1(x) + ... + p_k(x)$$.
We can find our secret number by finding the y-intercept of p:
$$a = p(0) = p_1(0) + ... + p_k(0)$$.

## Okay, where were we?
Oh yeah, solving a CTF problem. We initially assumed we could just get the flag by decrypting our shares, but looking at the Python file, that turned out not to be the case.

Instead, this is what the file does:
- Turns the bytestring "qxxxb, BuckeyeCTF admins, and NOT YOU" into an integer
- Encrypts the integer into 3 shares with k=3, and gives you the shares
- **Asks you for a replacement for the first share**
- Using the new set of 3 shares, decrypts the data
- If the decrypted data corresponds to the bytestring "qxxxb, BuckeyeCTF admins, and ME", it gives you the flag

What an odd problem. We need to reverse-engineer the decryption process to make it decrypt to a chosen value.

Luckily, it's pretty doable, and ends up being a single equation with a single unknown. Here's how we derive the equation (where a is the integer corresponding to "qxxxb, BuckeyeCTF admins, and ME"; $$y_2$$ and $$y_3$$ are the shares given to us; and $$y_1$$ is the new share we need to make):

$$\begin{align}a &= p(0) \\
a &= p_1(0) + p_2(0) + p_3(0) \\
a &= y_1 \frac{0-2}{1-2} \frac{0-3}{1-3} + y_2 \frac{0-1}{2-1} \frac{0-3}{2-3} + y_3 \frac{0-1}{3-1} \frac{0-2}{3-2} \\
a &= y_1 \frac{-2}{-1} \frac{-3}{-2} + y_2 \frac{-1}{1} \frac{-3}{-1} + y_3 \frac{-1}{2} \frac{-2}{1} \\
a &= 3 y_1 - 3 y_2 + y_3 \\
3 y_1 &= a + 3 y_2 - y_3 \\
y_1 &= (a + 3 y_2 - y_3)/3\end{align}$$

In order for $$y_1$$ to be an integer, we need to make sure $$a + 3 y_2 - y_3$$ is a multiple of 3.
We do this by netcatting over and over until this is true.

After a couple of tries, we get the flag!
```
I wrote down a list of people who are allowed to get the flag and split it into 3 using Shamir's Secret Sharing.
Your share is:
(1, 5633848164677390252701914670965270184760026556386817744129221631450069984002678101090048130422008563266639568759746726386131543239557666026346105273360573)
The other shares are:
(2, 502884063261798815389586773696637620038871059209008024629519145962728425380056300134268799627497812437351461043167950508188126504855877169128069033172684)
(3, 299800464877178076288866740674841206004236890401149246694572902707867350793435753874417341680884649201379366366068535858800318369082674734992347926779516)

Now submit your share for reconstruction:
>>> (1, 402950574969406123293297860138357218037458762408624942397994845060105975115594823577793944560504362875514609792063615319211978858358302884957112328024335)
Here's your flag:
buckeye{tH1s_SSS_sch3Me_c0uLd_u5e_s0M3_S1gna7Ur3s}
```