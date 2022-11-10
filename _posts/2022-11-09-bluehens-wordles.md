---
layout: post
current: post
cover: assets/bluehens/wordles/cover.png
navigation: True
title: "Wordles with Dads"
date: 2022-11-09 10:00:00
tags: [BlueHensCTF, misc]
class: post-template
subclass: 'post'
author: squ1rrel
---

Another variation of Wordle, just like my previous writeup on [Vocaloid Heardle](https://squ1rrel.dev/sekai-vocaloid-heardle).

-   [Kid (easy) Mode](#kid-easy-mode)
    -   [Problem Description](#problem-description)
    -   [Initial intuition](#initial-intuition)
    -   [When in doubt, scrape everything](#when-in-doubt-scrape-everything)
    -   [Getting the flag](#getting-the-flag)
-   [Dad (hard) Mode](#dad-hard-mode)
    -   [Problem Description](#problem-description-1)
    -   [Initial intuition](#initial-intuition-1)
    -   [Installing pwntools for the first time (and resorting to Docker)](#installing-pwntools-for-the-first-time-and-resorting-to-docker)
    -   [Getting the flag](#getting-the-flag-1)

## Kid (easy) Mode

### Problem Description

> Welcome to Dad Wordle:
> `nc 0.cloud.chals.io 29788`
>
> Source:
> https://gist.github.com/AndyNovo/0c35d07b460609fd457a9d1c5b8663d1
>
> Author: ProfNinja

### Understanding the problem

We were provided with the file `wordleswithdads.py` and an IP address & port `0.cloud.chals.io:29788` to connect to.

Looking at `wordleswithdads.py` (which is the source code for the game), it became clear that Wordles With Dads:

1. Has a list of dad jokes scraped from [icanhazdadjoke.com](https://icanhazdadjoke.com) & saved into `jokes.txt` (we have no access to it)
2. Loads one random joke from `jokes.txt` and reveals to the user the length of the joke as well as the first two characters.
3. With such limited information, the user has to guess what the joke is in 6 tries.
4. If the user guesses it correctly, the program returns the flag!

Also I noticed there is a `checkguess(answer, guess_in)` function that returns two arrays: `correct` and `position`:

-   `correct` stores the indices with correct character and correct position
-   `position` stores the indices with correct character but incorrect position

For example, if the `answer = ABCDEFG` and `guess_in = GFEDCBA`
Then `checkguess(answer, guess_in)` will return

-   `correct = [3]`
-   `position = [0, 1, 2, 4, 5, 6]`

which is exactly how Wordle works!

```python
def checkguess(answer, guess_in):
    if len(guess_in) != len(answer):
        print("Not the right guess length")
        return False
    if not alphacheck(guess_in):
        print("Invalid characters A-Z only")
        return False

    # histomaker returns the histogram of the alphabet positions
    # i.e. histomaker('ABA') will return
    #    {'A': [0, 2], 'B': [1], 'C': [], 'D': [], ..., 'Z': []}
    truth = histomaker(answer)
    guess = histomaker(guess_in)
    correct = []
    position = []
    for ltr in alphabet:
        tmp = guess[ltr]
        truetmp = truth[ltr]
        counter = 0
        for i in tmp:
            if i in truetmp:
                counter += 1
                correct.append(i)
        for i in tmp:
            if not i in correct:
                if len(truetmp) > counter:
                    counter += 1
                    position.append(i)
    correct.sort()
    position.sort()
    return {"correct": correct, "position": position}
```

### Initial intuition

My first intuition was to scrape all the dad jokes from [icanhazdadjoke.com](https://icanhazdadjoke.com) and implement a function called `search(length, start_with)` that returns jokes of given length and which starts with the two characters provided.

### When in doubt, scrape everything

Lucky for us, the website has an [API endpoint](https://icanhazdadjoke.com/api#search-for-dad-jokes) that allows us to scrape all the jokes using a simple function:

```python
import requests
search_url = "https://icanhazdadjoke.com/search"

# creates a jokes.txt file and insert all jokes scraped
# ... all the jokes are formatted the same way as `wordleswithdads.py`
def scrape():
    for page in range(22): # hard-coding 22 because there are 22 pages of jokes
        response = requests.get(search_url,
                                headers={"Accept": "application/json"},
                                params={"limit": 30, "page": page + 1}) # API only allows max 30 jokes per query
        joke_request = response.json()
        for joke in joke_request["results"]:
            # write to file
            with open("jokes.txt", "a") as joke_file:
                joke_file.write(joke["joke"] + "\n")
scrape()
```

Now we have a `jokes.txt` file that consists of 649 jokes:

```
# jokes.txt
I'm tired of following my dreams. I'm just going to ask them where they are going and meet up with them later.
Did you hear about the guy whose whole left side was cut off? He's all right now.
Why didn’t the skeleton cross the road? Because he had no guts.
...
```

If we look closer at the `wordleswithdads.py`, we would see that the jokes have all been sanitized to be A-Z only, where other characters have been removed.

Thus we need to implement a small function that formats our jokes in the same way as the provided code:

```python
# opens our existing jokes.txt and sanitize the jokes
# store the resulting jokes (sorted by length) into jokes_format.txt
def format():
    output = []
    with open("jokes.txt", "r") as joke_file:
        joke_list = joke_file.readlines()
        for joke in joke_list:
            # remove space
            s = joke.replace(" ", "")
            # capitalize
            s = s.upper()
            # remove non-alphabetic characters
            s = ''.join([i for i in s if i.isalpha()])
            output.append(s)

    # sort array by length
    output.sort(key=len, reverse=True)

    # write output to file
    with open("jokes_format.txt", "w") as joke_file:
        for joke in output:
            joke_file.write(joke + "\n")
format()
```

Now we have a `jokes_format.txt` file that looks like this:

```
# jokes_format.txt
TWOMUFFINSWERESITTINGINANOVENANDTHEFIRSTLOOKSOVERTOTHESECONDANDSAYSMANITSREALLYHOTINHERETHESECONDLOOKSOVERATTHEFIRSTWITHASURPRISEDLOOKANDANSWERSWHOAATALKINGMUFFIN
SOMEPEOPLESAYTHATCOMEDIANSWHOTELLONETOOMANYLIGHTBULBJOKESSOONBURNOUTBUTTHEYDONTKNOWWATTTHEYARETALKINGABOUTTHEYRENOTTHATBRIGHT
AMANWASCAUGHTSTEALINGINASUPERMARKETTODAYWHILEBALANCEDONTHESHOULDERSOFACOUPLEOFVAMPIRESHEWASCHARGEDWITHSHOPLIFTINGONTWOCOUNTS
...
```

### Getting the flag

As the saying goes: With great power comes great responsibility.

Now here's what you need to know before moving on: With a complete list of dad jokes comes the flag.

Now let's implement the `search()` function we've long awaited for!

```python
def search(length, start_with=''):
    search = []
    # load our database of jokes
    with open("jokes_format.txt", "r") as joke_file:
        # read the jokes line by line
        joke_list = joke_file.readlines()
        # iterate through the jokes
        for joke in joke_list:
            # get rid of white spaces
            joke = joke.strip()
            # if we get the right joke candidate, we add it to search
            if len(joke) == length and joke.startswith(start_with):
                search.append(joke)
    # return the list of jokes of given length & start with given characters
    return search

# this will print out list of likely candidates of length 44 and starts with 'WH'
print(search(44, 'WH'))
```

Now if we pass in the hints provided by the game into our `search()` function, we get a list of potential candidates. We can just keep trying until it works, which fortunately doesn't take that long.

Here is our flag: `UDCTF{S000_iPh0n3_ch4rg3rs_c4ll_3m_APPLE_JU1C3!}` 😎

## Dad (hard) Mode

### Problem Description

See challenge here: https://ctftime.org/task/23797

> In Hard mode you get 2 guesses, no hint, 10 problems and at most 60 seconds. But I don't think you need that much time honestly...
>
> Source: https://gist.github.com/AndyNovo/1a207eb7b6042686d6e447fa872e09e4
>
> Author: ProfNinja

### Initial intuition

Oh my god. This just became 100x harder. Not only do we have to play the game 10 times consecutively, we only have 2 guesses for each -- and only 60 seconds total!

This challenge actually reminded me of [Sekai CTF's Console Port Pro](https://2022.ctf.sekai.team/challenges/#Console-Port-Pro-38) -- kudos to [Akash](https://squ1rrel.dev/author/Ace314159/) for teaching me how pwntools works, because it was exactly the knowledge I needed to solve this challenge.

So my immediate intuition was to use pwntools to automate playing the game. 🤖

### Installing Pwntools for the first time (and resorting to Docker)

If you have never had any issues installing packages/tools, do you even CTF?

I immediately faced an issue while installing pwntools on my Mac, as this simple install script

```
$ pip3 install pwntools
```

Gave me an error:

```
note: This error originates from a subprocess, and is likely not a problem with pip.
  ERROR: Failed building wheel for unicorn
```

I am a busy person! I can't afford to waste time being stuck on installing packages >:(

In reality, I looked up everywhere online but still couldn't resolve the issue...

So I decided to try pulling a Docker image with pwntools installed. [This repo](https://github.com/Gallopsled/pwntools/blob/dev/DOCKER.md) taught me what I needed to do:

```
$ docker run -it pwntools/pwntools:stable
```

I wanted to automatically clean up the docker image when I close it, so I added `--rm`:

```
$ docker run --rm -it pwntools/pwntools:stable
```

Finally, I wanted to mount my current directory as the working directory in the container, so I added `-v "$(pwd):$(pwd)" -w "$(pwd)"` ([see cheatsheet](https://tutorials.releaseworksacademy.com/learn/confessions-of-a-programmer-my-docker-run-cheatsheet)):

```
$ docker run --rm -v "$(pwd):$(pwd)" -w "$(pwd)" -it pwntools/pwntools:stable
```

With this script, I am now able to run `python3 wordle_solver.py` with pwntools and even save my progress directly to my local current working directory!

### Getting the flag

The game now consists of 10 rounds.

So my plan was to write a function that plays one round of the wordle game, and put that function in an infinite loop until we win all 10 rounds.

After a lot of bug fixing, frustration, and polishing code, this is what my function looked like:

<!-- maybe show an image of how pwntool works -->

```python
def play_one_round():
    # read game start message (which includes joke length)
    welcome_to_dad_joke_msg = str(r.recvline())

    # get the joke length (it's stored in the 8th word)
    length = int(welcome_do_dad_joke_msg.split(' ')[8])

    # search for all jokes of this length
    db = search(length)

    # read away useless line
    r.recvuntil('Guess? >')

    # print out what we are guessing
    print(f"{'Guess #1:':<30}{db[0]:<40}")

    # send our first guess to game server
    r.sendline(db[0])

    # read away useless line
    r.recvline()

    # response will return msg that hints to us if correct/wrong
    response = str(r.recvline())

    # print out what our response is
    print(f"{'Response 1:':<30}{response:<40}")

    # guess is not correct if we can find 'position' and 'correct' in the response (both are arrays)
    if 'position' in response and 'correct' in response:
        print('[Guess is Wrong]')

        # get ready for next guess
        r.recvuntil("Guess? >")

        # parseStats() will return the arrays correct, position from the response string
        correct, position = parseStats(response)

        # get the most likely candidate satisfying the given correct & position arrays
        candidates = getCandidates(correct, position, db[0], db)

        # no candidates found :( which means that sth went wrong so go into interactive mode to debug
        if len(candidates) == 0:
            print("[No candidates]")
            r.interactive()

        # at least one candidate found, so let's guess with that
        else:
            # print out what we are guessing
            print(f"{'Guess #2:':<30}{candidates[0]:<40}")

            # send our second guess to game server
            r.sendline(candidates[0])

            # receive response
            response = str(r.recvline())

            # print out what our response is
            print(f"{'Response 2:':<30}{response:<40}")

            # sad
            if str(r.recvline()) == "You lose":
                print('[Guess 2 Wrong]')
                # we failed :(
                return False

    # guess is correct!!!
    else:
        print('[Guess 1 Correct]')
        # yay!
        return True

    # if we reach here it probably means we didn't guess right
    return False
```

Finally, in the `main` function we can call this function repeatedly until we win 10 rounds!

```python
from pwn import *

# connect to the game server
r = remote("0.cloud.chals.io", 33282)

# read away the first useless line
r.recvline()

def restart_game():
    r.close()
    r = remote("0.cloud.chals.io", 33282)
    r.recvline()

def main():
    # start playing!
    games_won = 0
    while True:
        if play_one_round():
            games_win += 1
        else:
            games_won = 0
            restart_game()
            print("It's okay. We try again")
            continue

        if games_won >= 10:
            print('-------------------------------------------')
            print('We did it..!')
            print('-------------------------------------------')
            r.interactive()
            break

main()
```

It didn't work out when I first ran it, but after a few more attempts, we got the flag!!

The flag: `UDCTF{wh4ts_th3_be5t_th1ng_ab0ut_Sw1tzerl4nd? Dunn0_bu7_th3_flag_15_a_b1g_plu5!}` 🎉