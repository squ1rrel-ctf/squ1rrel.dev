---
layout: post
current: post
cover: assets/kitctf/holden/cover.png
navigation: True
title: "Prime Guesser 1 & 2"
date: 2022-12-27 10:00:00
tags: [KITCTFCTF, crypto]
class: post-template
subclass: 'post'
author: holden
mathjax: true
mermaid: true
---

Who needs math when you can just guess?

## The Challenge
In this challenge, a connection to the server is opened and the user is immediately bombarded with two lists of numbers.
```
377962,200034,230557,610044,171667,86688,943151,848941,382931,961223,705385,729217,185385,442830,149549,116951,679483,499023,706614,477131,13777,65174,442175,377983,814558,984299,115508,235243,232673,166789,809773,856798,526446,675718,399685,874823,303414,495553,749816,787954,573900,439826,832348,563436,1039490,82861,697843,988802,888514,249047,790497,76606,188407,91832,667104,674584,208913,242545,717322,384867,757719,977174,927325,140953
245003,564865,423551,794916,1030099,715438,951297,104647,51670,129918,793465,528650,939860,52534,990641,781658,964589,582634,823047,235310,794195,473151,338700,945267,800066,967209,304320,684236,765430,832074,499153,735036,838025,447156,527498,524078,154154,878862,374040,322169,318428,815100,447328,217752,140044,266616,902978,853001,698526,261289,392639,763882,260894,665244,874182,1031487,207823,842837,81426,398136,945841,950746,1025753,214976
```
Thereafter, the server asks the user what they want. The server does not provide any options for the user; however, looking at the code shows that there are three acceptable actions.
```python
while True:
    choice = int(input("What do you want?\n").strip())
    if choice == 0:
        number_input = int(input("What do you want to encrypt?\n").strip(), 10)
        if number_input > 20 or number_input < 1:
            print("Thats out of bound")
        else:
            outputCipher(smart_enrypt(number_input))
    elif choice == 1:
        cipher_input = input("What is the first part of the Cipher?\n").strip()
        c0 = [int(n, 10) for n in cipher_input.split(",")]
        cipher_input = input("What is the second part of the Cipher?\n").strip()
        c1 = [int(n, 10) for n in cipher_input.split(",")]
        c = (c0, c1)
        oracle(c)
    elif choice == 2:
        break
```

### Option 0
In option 0, the user can give the server a number in the range $$[1, 20]$$ for the server to encrypt. Once the number is encrypted, its entire output is returned to the user. Now this might initially seem incredibly useful; however, the restriction of input numbers in the range $$[1, 20]$$ really does not provide too much information. Here is an example output:
```
What do you want?
0
What do you want to encrypt?
1
80332,463780,792058,383640,670434,322669,186514,632518,109001,205518,245703,667775,838329,73292,494435,143250,1017494,875545,706464,46307,370376,760305,1010088,952492,758982,392160,934753,734356,937534,12157,935728,878926,392830,640827,165465,81185,91633,397062,573058,736689,897346,627208,1009605,405665,339680,833796,1032471,218936,475816,835618,1470,298054,793452,881959,562408,328171,506307,756656,844538,503920,725078,565773,1017419,164483
985494,73081,120524,1017959,318357,306968,634004,727418,527224,158725,753912,904952,814567,319821,317262,358766,793112,935679,658026,146112,753484,143127,1048145,902333,762674,563732,761630,638022,1007232,747055,750481,56746,303755,819763,1014514,673684,844447,820666,724373,731507,63228,735920,602701,437707,343858,1024297,334425,261636,519396,422632,520735,977994,770901,822921,367960,566980,402892,774181,811351,317380,480510,360153,895582,331365
```
### Option 1
In option 1, the user passes the server two lists of ciphertext, and after decrypting, the `oracle()` function is called which reveals whether the first index (0) of the decryption is equal to $$0$$.
```python
def oracle(c):
    p = decrypt(sk, n, q, t, poly_mod, c)
    print(p == 0)
```
Here is an example output using the ciphertext from Option 1 above.
```
What do you want?
1
What is the first part of the Cipher?
80332,463780,792058,383640,670434,322669,186514,632518,109001,205518,245703,667775,838329,73292,494435,143250,1017494,875545,706464,46307,370376,760305,1010088,952492,758982,392160,934753,734356,937534,12157,935728,878926,392830,640827,165465,81185,91633,397062,573058,736689,897346,627208,1009605,405665,339680,833796,1032471,218936,475816,835618,1470,298054,793452,881959,562408,328171,506307,756656,844538,503920,725078,565773,1017419,164483
What is the second part of the Cipher?
985494,73081,120524,1017959,318357,306968,634004,727418,527224,158725,753912,904952,814567,319821,317262,358766,793112,935679,658026,146112,753484,143127,1048145,902333,762674,563732,761630,638022,1007232,747055,750481,56746,303755,819763,1014514,673684,844447,820666,724373,731507,63228,735920,602701,437707,343858,1024297,334425,261636,519396,422632,520735,977994,770901,822921,367960,566980,402892,774181,811351,317380,480510,360153,895582,331365
False
```
### Option 2
In option 2, the user simply breaks from the menu option loop and is then subsequently asked for the factors of a randomly generated prime number whose ciphertext was provided prior. Here is an example output:
```
What do you want?
2
What are the factors?
3,5,7
Failed
```
## Overall Program Function
In order to get the flag from the server, the prime factors of the randomly generated number must be guessed correctly 100 times in a row. Menu options 0 and 1 above can be repeated as many times as the user would like within each loop to gather any necessary information. Here is a graph of the process:

<div class="mermaid">
flowchart LR
    classDef default fill:#5978cf,stroke:#000,color:#000
    classDef green fill:#64c452,stroke:#000,color:#000
    classDef red fill:#a52a2a,stroke:#000,color:#000
    classDef purple fill:#68228b,stroke:#000,color:#FFF
    classDef orange fill:#cc5500,stroke:#000,color:#FFF
    classDef white fill:#FFF,stroke:#000,color:#000

    linkStyle default fill: none, stroke: white: 

    i("i=0"):::orange
    Q("i<100?"):::purple
    M("Prompt menu"):::purple
    A("Prompt number")
    B("Prompt ciphertexts")
    C("Exit menu")
    ENC("Encrypt"):::orange
    DEC("Decrypt"):::orange
    ORC("Oracle"):::orange
    G("Guess primes"):::purple
    E("Program exits"):::red
    F("Print flag"):::green
    IP("i++"):::white

    i-->Q
    Q--"True"-->M
    Q--"False"-->F

    M--"Option 0"-->A
    M--"Option 1"-->B
    M--"Option 2"-->C

    A-->ENC-->M
    B-->DEC-->ORC-->M
    C-->G

    G--"Incorrect"-->E
    G--"Correct"-->IP-->Q
</div>

## Encryption Analysis
Now that we understand the program's flow, we must delve deeper. Since this is a cryptography challenge we need to actually look at what's going on behind the scenes, and if we are lucky there will be a simple way to break the encryption and decrypt the random number's ciphertext each round. However, before we explore the encrpytion and decryption functions, there are some global variables we should cover:

```python
# polynomial modulus degree
n = 2**6 # EXAMPLE !!! ON THE SERVER ARE OTHER NUMBERS
# ciphertext modulus
q = 2**20 # EXAMPLE !!! ON THE SERVER ARE OTHER NUMBERS
# plaintext modulus
t = 2**10 # EXAMPLE !!! ON THE SERVER ARE OTHER NUMBERS
# polynomial modulus
poly_mod = np.array([1] + [0] * (n - 1) + [1])
pk, sk = keygen(n, q, poly_mod)
```
I've gone through the painstaking trouble of politely labelling each variable up above, and the creators of the challenge were also so helpful in informing us that none of these variables are the same as on the server. However, they did provide a general formula for their creation; that is, $$n$$, $$q$$, and $$t$$ were all of the form $$2^i$$ where $$i\in\mathbb{Z}^*$$. (Surely, $$i$$ cannot be *too* big or else this program would be unmanageable?) Nonetheless, while the form of these variables is known, they are still to be considered unknown. What's perhaps more interesting than these three variables is `polyMod`, which takes the form:

```python
array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
```

What significance does this have? I did not know at this point, but nonetheless it is fully determined by the value of $$n$$, which is good since that means that finding $$n$$ gives the value of two global variables used in encryption. The final two global variables are $$pk$$ and $$sk$$, which are generated by a function named `keygen` that accepts $$n$$, $$q$$, and `polyMod` as arguments.

```python
def keygen(size, modulus, poly_mod):
    sk = gen_binary_poly(size)
    a = gen_uniform_poly(size, modulus)
    e = gen_normal_poly(size)
    b = polyadd(polymul(-a, sk, modulus, poly_mod), -e, modulus, poly_mod)
    return (b, a), sk
```

Now this is the point in the cryptography analysis that randomness joins the party and really puts a damper on my mood. Randomness is required in ciphers to make them *confusing* and *complex*, and it sure does make my life difficult in CTFs. Anyway, `keygen` calls four unique separate functions: `gen_binary_poly`, `gen_uniform_poly`, `gen_normal_poly`, and `polyadd`. The code for these is short and sweet (though clustered), so let's take a look.

### polyadd
```python
def polyadd(x, y, modulus, poly_mod):
    return np.int64(np.round(poly.polydiv(poly.polyadd(x, y) % modulus, poly_mod)[1] % modulus))
```
Let's start with `polyadd`. It's pretty simple if you don't look too much into it (I did and wouldn't recommend it) -- it essentially adds two polynomials $$x$$ and $$y$$ that are represented by a list of their coefficients, and then divides them by `polyMod` and takes the remainder. For example, let's look at equations of degree 4:
  
$$\begin{align}
f(x)&=1x^4-27x^3+14x^2+0x+120 \\
g(x)&=1x^4+3x^3+4x^2-11x-30 \\
polymod(x)&=1x^5+0x^4+0x^3+0x^2+0x+1
\end{align}
$$
  
Each of these polynomials would have a list representation like this:
```python
f         = array([1, -27, 14,   0, 120])
g         = array([1,   3,  4, -11, -30])
poly_mod  = array([1, 0, 0, 0, 0, 1])
```

Calling `polyadd` with these two equations would first add them:  
$$f(x)+g(x)=2x^4-24x^3+18x^2-11x+90$$

Subsequently, they would be divided by `polyMod`: 
$$\frac{f(x)+g(x)}{polymod(x)}=\frac{2x^4-24x^3+18x^2-11x+90}{1x^5+0x^4+0x^3+0x^2+0x+1}$$

This polynomial division would then yield a divided portion and a remainder. 
The remainder is taken as it is guaranteed to have a maximum degree of $$4$$; 
hence why `polyMod` was named the *polynomial modulus* above.

### polymul
```python
def polymul(x, y, modulus, poly_mod):
    return np.int64(
        np.round(poly.polydiv(poly.polymul(x, y) % modulus, poly_mod)[1] % modulus)
    )
```

This function is not actually called by `keygen` at all, but it's fitting to discuss it after `polyadd` since they are essentially the same thing (and this is used in the encryption function). I'm not going to delve into great detail here, but it functions exactly the same as `polyadd`, except that instead of polynomial addition, polynomial multiplication (or convolution) occurs!

### gen_binary_poly
```python
def gen_binary_poly(size):
    return np.random.randint(0, 2, size, dtype=np.int64)
```

The name of this function is quite straightforward -- it creates a polynomial list of coefficients that are either $$0$$ or $$1$$. For example, calling `gen_binary_poly(5)` would yield: 

```python
array([1, 0, 1, 1, 1])
```

Which is equivalent to the polynomial $$f(x)=1x^4+0x^3+1x^2+1x+1$$.

### gen_uniform_poly
```python
def gen_uniform_poly(size, modulus):
    return np.random.randint(0, modulus, size, dtype=np.int64)
```
This function acts much the same as `gen_binary_poly` but instead of giving the generated polynomial coefficients of $$1$$ or $$0$$, it gives the generated polynomial coefficients based on a uniform distribution (i.e. a random distribution). The result of `gen_uniform_poly(5, 10)` could be something like:
```python
array([3, 6, 5, 1, 9])
```

Which is equivalent to the polynomial $$f(x)=3x^4+6x^3+5x^2+1x+9$$.

### gen_normal_poly
```python
def gen_normal_poly(size):
    return np.int64(np.random.normal(0, 2, size=size))
```
Just as with `gen_uniform_poly` and `gen_binary_poly`, this function generates a list of coefficients of a random polynomial but samples them from a normal distribution with $$0$$ as the center and $$-2$$ and $$2$$ being the minimum and maximum respectively. The result of `gen_normal_poly(5)` could be something like this:
```python
array([-2, 1, 2, 0, 0])
```
Which is equivalent to the polynomial $$f(x)=-2x^4+1x^3+2x^2+0x+0$$.

### Encryption Function Analysis
Now that all of the pesky helper functions have been discussed, we can finally talk about the encryption function! The encryption function accepts six arguments: `pk, size, q, t, polyMod, and pt`.
```python
def encrypt(pk, size, q, t, poly_mod, pt):
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m  % q
    e1 = gen_normal_poly(size)
    e2 = gen_normal_poly(size)
    u = gen_binary_poly(size)
    ct0 = polyadd(
            polyadd(
                polymul(pk[0], u, q, poly_mod),
                e1, q, poly_mod),
            scaled_m, q, poly_mod
        )
    ct1 = polyadd(
            polymul(pk[1], u, q, poly_mod),
            e2, q, poly_mod
        )
    return (ct0, ct1)
```

There is a lot going on in this function, so to lessen your confusion (and totally not mine), I've put in hours of hard labour to create this graph:
<div class="mermaid">
 graph TD
    classDef default fill:#5978cf,stroke:#000,color:#000
    classDef input fill:#64c452,stroke:#000,color:#000
    classDef function fill:#c97038,stroke:#000,color:#000


    variables
    functions:::function
    A("function arguments"):::input
</div>
 
<div class="mermaid">
graph TD
    classDef default fill:#5978cf,stroke:#000,color:#000
    classDef input fill:#64c452,stroke:#000,color:#000
    classDef function fill:#c97038,stroke:#000,color:#000

    size:::input--> m
    pt:::input--> m

    q:::input-->delta
    t:::input-->delta

    m --> scaled_m
    delta --> scaled_m
    q:::input--> scaled_m


    size --> gen_normal_poly
    size --> gen_binary_poly
    gen_normal_poly:::function --> e1
    gen_normal_poly:::function --> e2
    gen_binary_poly:::function --> u

    pko:::input --> ct0
    u --> ct0
    q --> ct0
    poly_mod:::input --> ct0
    e1 --> ct0
    scaled_m --> ct0

    pk1:::input --> ct1
    u --> ct1
    q --> ct1
    poly_mod -->ct1
    e2 --> ct1
</div>

It's real pretty isn't it? While it is pretty scattered and complex, it does give us two key insights:
1. The number encrypted, `pt`, is manipulated into `m`, then `scaledM`, and then ends up somewhere within `ct0`.
2. I do not know what is going on.
  
In light of this second insight, I thought it was best to simply ignore the encrypt function for a while and move onto decryption since that is what we are *really* interested in.

### Decryption Function Analysis
Now, the decryption function is interesting because it is *far* simpler than the encryption function. This told me that a bunch of the information in the encrypt function is only there to confuse us.

```python
def decrypt(sk, size, q, t, poly_mod, ct):
    scaled_pt = polyadd(
            polymul(ct[1], sk, q, poly_mod),
            ct[0], q, poly_mod
        )
    decrypted_poly = np.round(scaled_pt * t / q) % t
    return int(decrypted_poly[0])
```  

The decrypt function still takes a total of six arguments; however, it only performs 2 polynomial operations: `polymul` and `polyadd`. Here is another chart for you to stare at.
<div class="mermaid">
  graph LR
    classDef default fill:#5978cf,stroke:#000,color:#000
    classDef input fill:#64c452,stroke:#000,color:#000
    classDef function fill:#c97038,stroke:#000,color:#000

    sk:::input --> polymul
    ct1:::input --> polymul
    q:::input --> polymul
    poly_mod:::input --> polymul:::function

    polymul --> polyadd:::function
    ct0:::input --> polyadd
    q:::input ---> polyadd
    poly_mod:::input --> polyadd

    polyadd --> scaled_pt

    t:::input --> decrypted_poly
    q:::input --> decrypted_poly
    scaled_pt --> decrypted_poly

    decrypted_poly --First Index--> return
</div>

What's even better about the decrypt function is that it does not involve any randomly generated polynomials or weird operations; it is straightforward. Since it was provided to us, and the arguments are those that we know the form of, it made sense to simply try and determine the global variable values to input -- and what better way to do this than the provided menu options!

### Finding n
I decided to start with the easiest variable to find first, and unsurprisingly this was $$n$$. Remember the ciphertext of the randomly generated number? Well, turns out its size is $$n$$, so simply doing a little processing to turn the input into a list allows for $$n$$ to be found. 
> $$n$$ is often referred to as `size` within functions.

```python
def stringToList(str):
    regex = R"\w*[^[,\s\]]"
    matches = re.findall(regex, str)
    num = [int(m) for m in matches]
    return num
```
```python
if __name__ == "__main__":
    # CURRENT ENCRYPTED NUMBER
    ct0_str = conn.recvline(keepends=False).decode('utf-8')
    ct1_str = conn.recvline(keepends=False).decode('utf-8')
    ct0 = stringToList(ct0_str)
    ct1 = stringToList(ct1_str)
    ct = [ct0, ct1]

    n = len(ct1)
    ...
```

### Finding q
The menu option that is most intriguing for discovering the server's global encryption variables is Option 1, since it is what actually calls the decryption function. After some intense mathematical thought that Euler and Galois would envy, I recognized a method for finding the `Q` global variable. In the decrypt function, the known variable `ct_1` is multiplied by the unknown `sk` and then subsequently added to the known `ct_0`. Therefore, if I want to know the output of these polynomial operations, it would be best to rid `sk` from the equation, and what better way to do that then having `ct1` be the zero polynomial such that their polynomial product is the zero polynomial? Thereafter, since I know `ct_0`, I will know the output of the polynomial operations, `scaledPT`, since the zero polynomial is an additive identity. Using `scaledPT`, `q` can be found from the result of `decryptedPoly`'s calculation: $$decryptedPoly=\frac {scaledPT\cdot t}{q}\hspace{0.3cm} mod \hspace{0.15cm}t$$

My naive (but brilliant) thought at the time of this challenge was that if I simply set all elements of `ct_0` to be the same number and of the form $$2^i$$ where $$i\in\mathbb{Z}^\*$$, then I will be able to find `q` when the value of `ct_0`'s elements are equal to `q` since $$\frac{q\cdot t}{q} = t = 0 \hspace{0.3cm}mod\hspace{0.15cm}t$$. I wrote the following script to accomplish this locally:

```python
def findQ(size, maxI):
    Q = -1
    for i in [2**i for i in range(1, maxI)]:
        conn.sendline(b'1')
        conn.recvline()
        ct = []
        ct.append([0])
        ct.append([0] * size)
        ct[0] = [i]*64
        
        conn.sendline(listToBytes(ct[0]))
        conn.recvline()
        conn.sendline(listToBytes(ct[1]))
        
        orcStr = conn.recvline(keepends=False).decode('utf-8')
        orc = False
        if orcStr == "True":
            orc = True

        print("iter: ", int(log2(i)), "\ti: ", i, "\t", orc)
        if orc:
            Q = i
            break
        conn.recvline()
    return Q
```
However, the output of this script was confusing and didn't match my expectations at all. I removed the `break` statement and let it run through all iterations to see the result -- and the results are shocking!
```
FINDING Q
iter:  1        i:  2            True
iter:  2        i:  4            True
iter:  3        i:  8            True
iter:  4        i:  16           True
iter:  5        i:  32           True
iter:  6        i:  64           True
iter:  7        i:  128          True
iter:  8        i:  256          True
iter:  9        i:  512          True
iter:  10       i:  1024         True
iter:  11       i:  2048         True
iter:  12       i:  4096         True
iter:  13       i:  8192         True
iter:  14       i:  16384        True
iter:  15       i:  32768        True
iter:  16       i:  65536        True
iter:  17       i:  131072       True
iter:  18       i:  262144       True
iter:  19       i:  524288       True
iter:  20       i:  1048576      False
iter:  21       i:  2097152      False
iter:  22       i:  4194304      False
iter:  23       i:  8388608      False
iter:  24       i:  16777216     False
iter:  25       i:  33554432     False
iter:  26       i:  67108864     False
iter:  27       i:  134217728    False
iter:  28       i:  268435456    False
iter:  29       i:  536870912    False
iter:  30       i:  1073741824   False
iter:  31       i:  2147483648   False
iter:  32       i:  4294967296   True
```
It started with all True, turned False, and then turned back True again? Unusual, but expected considering I did some horrible math with the `decryptedPoly` equation. Nonetheless, for a while I just circumvented this by setting a flag to wait for the first False and then break on the next `True` statement and return `i`. After some tests locally, this successfully found $$Q$$ everytime!

### Finding t
Moving on to the next variable, I decided to try and find `t`. Now, I don't know what happened during some of this period. I was losing my sanity more and more with each run of my script; however, I stumbled upon a fun little coincidence. Remember the unusual output from finding $$q$$? Well it turns out that the number of `False` statements is the power of `t`! How did I figure this out? I don't know, it came to me in a dream (not really, I barely slept that night). Regardless, I went about changing the power of `t` several times and each time this statement held true. Therefore, at the time I did not question anything and just went with it; however, after having slept I can now provide an explanation. 

Consider $$2^P2^T2^{-Q}=2^{P+T-Q}$$ where $$P$$, $$T$$, and $$-Q$$ are the powers of $$2$$ for $$p$$, $$q$$, and $$t$$.  
Now, assuming $$Q>T$$, then while $$P<(Q-T)$$ a negative exponent will result, and thus a fraction. Since these values are base $$2$$ the largest fraction possible is $$\frac{1}{2}$$ which `np.round` evaluates to 0, which causes `oracle` to return `True`. However, once $$P>(Q-T)$$ a positive exponent will result which causes a value larger than $$1$$ and a subsequent `False` from `oracle`. This string of `False`s will continue until $$P=Q$$, in which case the result of the equation is $$2^T$$ which $$mod \hspace{0.15cm}t$$ is $$0$$.

```python
def findQandT(size, maxI):
    falseFound = False
    Q = -1
    T = -1

    Ti = 0
    for i in [2**i for i in range(1, maxI)]:
        conn.sendline(b'1')
        conn.recvline()
        ct = []
        ct.append([0])
        ct.append([0] * size)
        ct[0] = [i]*64
        conn.sendline(listToBytes(ct[0]))
        conn.recvline()
        conn.sendline(listToBytes(ct[1]))
        orcStr = conn.recvline(keepends=False).decode('utf-8')
        orc = False
        if orcStr == "True":
            orc = True

        print("iter: ", int(log2(i)), "\ti: ", i, "\t", orc)
        if not orc and not falseFound:
            falseFound = True
            Ti = int(log2(i))
        if falseFound and orc:
            Q = i
            T = 2**(int(log2(i))-Ti)
            break
        conn.recvline()
    return Q, T
```

### Finding sk
The next variable (and the most difficult) I decided to find was `sk`. Now `sk` is different from `q` or `t` in that it is actually a list of values rather than just a single constant. Ignoring this fact for the moment I used a similar technique to finding `q` and `t`, but instead made `ct_1` all $$1$$s and then made `ct_0` all $$0$$s. The thought behind this was that if I multiply `ct_1` by `sk` it might give me some information on `sk`. However, what I received after printing `scaledPT` locally was that it was all $$1$$s. This made some sense considering `polymul` is basically a convolution followed by a deconvolution, and so I decided to instead just make the first element of `ct_1` a $$1$$. What I received was the following:
```python
  SCALED_PT [ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
```

Now this looked more promising! Comparing it to the actual value of `sk` I received:
```python
    SK        [ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 ]
    SCALED_PT [ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
```
Noticing something fishy? They're the same! Well, almost. Some of the elements of `scaledPT` are lost due to the polynomial division. However, this was good news. The next problem was that I was only able to check the first element of `scaledPT` and so I needed some way to shift `scaledPT`. Knowing that `polymul` is basically a convolution, I had a suspicion that shifting the index of `ct_1` that was a $$1$$ would give me this shift. Thus, I decided to write a script that would output to a file this result for every index of `i` being set to $$1$$. The results may shock you:

```python
SK:
[ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 ]

SCALED_PT:
[ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
[ 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
[ 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
[ 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 ]
[ 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 ]
[ 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 ]
[ 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 ]
[ 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 ]
[ 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 ]
[ 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 ]
[ 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 ]
[ 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 ]
[ 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 ]
[ 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 ]
[ 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 ]
[ 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 ]
[ 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 ]
[ 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 ]
[ 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 ]
[ 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 ]
[ 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 ]
[ 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 ]
[ 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 ]
[ 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 ]
[ 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 ]
[ 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 ]
[ 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 ]
[ 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 ]
[ 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 ]
[ 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 ]
[ 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 ]
[ 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 ]
[ 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 ]
[ 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 ]
[ 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 ]
[ 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 ]
[ 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 ]
[ 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 ]
[ 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 ]
[ 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 ]
[ 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 ]
[ 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 ]
[ 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 ]
[ 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 ]
[ 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 ]
[ 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 ]
[ 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 ]
[ 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 ]
[ 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 ]
[ 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 ]
[ 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 ]
[ 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 ]
[ 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 0 1 ]
[ 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 ]
[ 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 1 ]
[ 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 ]
[ 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 0 0 0 1 ]
[ 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 ]
[ 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 ]
[ 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 ]
[ 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 1 ]
[ 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 0 0 1 ]
[ 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
[ 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 ]
```

Now, I'm no genius, but just looking at this pattern and seeing the darker (or lighter for you lightmode freaks) streaks along the diagonal told me that my suspicion was correct. So, I wrote a script to get the first element of each of the above arrays and...
```python
SK:         [ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 ]
SCALED_PT:  [ 0 0 1 0 1 1 1 0 0 0 0 1 0 0 0 1 1 0 1 1 1 0 1 0 0 0 1 0 0 0 0 1 0 1 0 0 1 0 1 0 1 1 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 0 0 0 1 1 0 0 ]
```
They don't match? Maybe it just needs to be shifted? I wrote a short program to do this, yet still there were only 32 matching characters for all possible in-order shifts of the `scaledPT`. Perhaps in reverse?
 ```python
SK:         [ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 ]
SCALED_PT:  [ 0 0 1 1 0 0 0 1 1 1 0 1 0 0 0 0 0 1 0 1 1 1 1 1 0 1 0 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1 0 1 1 0 0 0 1 0 0 0 0 1 1 1 0 1 0 0 ]
```

Yes, in reverse. Don't ask me why this works. It just did; it came to me in a dream (Edit: I also had to shift it by $$1$$). However, this meant that `sk` could be found! One small issue though: running the script locally just returned a bunch of $$0$$s. Remeber the modulo function above? Well, `numpy.round` is called on the result of the entire function and so whatever you input must be greater than $$0.5$$ for `oracle` (function that tells you whether the first element is $$0$$ or not) to give you a `False` return: `False` -> `scaledPT != 0`. So instead of setting to $$1$$, I actually set the value to $$Q\*2/3$$. Why this value, you might ask? I do not know, it just felt like a non-problematic value since it was neither `q` nor `t` and was greater than $$\frac{1}{2}t$$. Running the program this time resulted in success and I therefore had a method to solve for `sk`! Here is the code:

```python
def findSK(size, q):
    sk_guess_str = ""
    for i in range(size):
        conn.sendline(b'1')
        conn.recvline()
        ct = []
        ct.append([0] * size)
        ct.append([0] * size)
        ct[1][i] = int(round(q*2/3))
        conn.sendline(listToBytes(ct[0]))
        conn.recvline()
        conn.sendline(listToBytes(ct[1]))
        orcStr = conn.recvline(keepends=False).decode('utf-8')
        orc = 1
        if orcStr == "True":
            orc = 0
        print("iter: ", i, "\t", orcStr, "\t", orc)
        sk_guess_str += str(orc)
        conn.recvline()
        ct[1][i] = 0
    sk_guess_str = sk_guess_str[::-1]
    sk_guess_str = sk_guess_str[-1] + sk_guess_str[0:-1]
    sk_guess = [int(i) for i in sk_guess_str]
    return sk_guess
```

## Prime Guesser 1 Solution
After finding methods to solve for `n`, `q`, `t`, and `sk`, `polyMod` could be created in the same manner given in the source code, and as `ct` was given, all necessary variables for decryption were solvable. Finding the factors of the numbers was possible using the relevant `get_factors(number)` script provided in the source code. Putting all these pieces together in a script and running them locally, I found success, even with local variables changed. Thereafter, I ran it on the server, and it worked! I passed 100 prime guessing trials and received the flag.

## Prime Guesser 2 Solution
At the time of solving *Prime Guesser 1*, it was ~7 AM and I had not slept out of frustration with the problem. Nonetheless, I decided to just take a peek at *Prime Guesser 2*, the continuation of *Prime Guesser 1*. I was met with potentially one of the best surprises ever: to my amazement, they were basically the same! *Prime Guesser 2* was the same as *Prime Guesser 1* but lacked the encryption menu option (Option 0). Since my solution for *Prime Guesser 1* did not utilize the function at all, my solution worked for both *Prime Guesser 1* and *Prime Guesser 2*! 

## Conclusion
This is only my second ever CTF and I have only ever done crypto challenges (due to my inexperience in all other categories). However, I had a lot of fun with these challenges and would like to thank everyone at KITCTF for putting on the competition. Before I get any hatemail about the horrible state of the solution code, let it be known that I wrote a majority of this after being awake for 24+ hours and was mentally (and spiritually?) exhausted. I considered improving it to my standards while writing this; however, I think it holds more true to the CTF environment and pressure that I don't. If you read through all of this, I appreciate your time and support -- thank you!

<sub>If you have any comments or questions please shoot me a message. Thanks again for reading!</sub>
