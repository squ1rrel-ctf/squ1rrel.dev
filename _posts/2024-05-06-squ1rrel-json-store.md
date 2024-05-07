---
layout: post
current: post
cover:  assets/squ1rrel/nisala/json-store/cover.webp
navigation: True
title: "JSON Store"
date: 2024-05-06 09:57:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: nisala
---

Have you ever wanted to store some JSON data really quickly? Have we got the solution for you!

This challenge has the highest number of solves in web, with 74 solves. I created this challenge because when the `taffydb` exploit dropped a few years ago, I was absolutely amazed. This package was getting millions of downloads a week, and it was insanely vulnerable. I checked on it recently, and it still gets half a million weekly downloads, despite massive warnings all over the internet about its vulnerabilities. I figured this would make for a perfect beginner challenge.

# Step 1: Getting our bearings

The interface for this challenge is pretty simple -- we can enter our username, and store arbitrary un-nested string data in a JSON format with our username. We can store as many JSONs as we want under our username, and they can share keys or have different keys.

We can also query these JSON "rows" (different JSON documents) by submitting another JSON with different keys and their corresponding values, and the website will show all rows that matches the key-value pairs that are specified in this JSON (for the provided username, of course).

![Image of the challenge website](/assets/squ1rrel/nisala/json-store/challenge-site.png)

The data storage and filtering are managed by a package called `taffy`:

```js
const TAFFY = require("taffydb").taffy;

const db = TAFFY([
    {"username": "admin", "comments": process.env.FLAG},
    {"username": "randomuser", "comments": "This is a test comment"},
]);
```

And look, the flag's in there too! But we can't query it directly -- `admin` is not an allowed username. We'll have to get it some other way.

## Step 2: Learning about taffy

taffy's a weird choice for a database, so there must be a reason it was chosen. Let's Google around for `taffy`.

![Image of the challenge website](/assets/squ1rrel/nisala/json-store/google.png)

![Image of the challenge website](/assets/squ1rrel/nisala/json-store/npm.png)

Well, well, well. What could this be?

> Affected versions of this package are vulnerable to Internal Property Tampering. taffy sets an internal index for each data item in its DB. However, it is found that the internal index can be forged by adding additional properties into user-input. If an index is found in the query, taffyDB will ignore other query conditions and directly return the indexed data item. Moreover, the internal index is in an easily-guessable format (e.g. T000002R000001). As such, attackers can use this vulnerability to access any data items in the DB and exploit an SQL Injection.

Amazing. It looks like all we have to query for is the ID of the first element, which is always the same, and a property called `___s`.

## Step 3: Running the exploit

Let's try the provided exploit.

![Image of the challenge website](/assets/squ1rrel/nisala/json-store/badexploit.png)

Invalid JSON? Right, because `true` is not a string. Let's change it to `"true"` (filled strings evaluate to true):

![Image of the challenge website](/assets/squ1rrel/nisala/json-store/goodexploit.png)

And there's our flag.

You can also see that IDs are easily guessable by simply submitting a bunch of data items under your username.

![Image of the challenge website](/assets/squ1rrel/nisala/json-store/guessable.png)

The IDs are sequential, so it's trivial to find the ID of the flag, and then request it with the `___s` attribute set.