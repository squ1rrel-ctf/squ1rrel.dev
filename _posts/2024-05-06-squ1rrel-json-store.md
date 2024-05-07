---
layout: post
current: post
cover:  assets/squ1rrel/nisala/jsonp-store/cover.png
navigation: True
title: "JSON Store"
date: 2024-05-06 09:57:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: nisala
---

challenge description

# Step 1: Getting our bearings

The interface for this challenge is pretty simple -- we can enter our username, and store arbitrary un-nested string data in a JSON format with our username. We can store as many JSONs as we want under our username, and they can share keys or have different keys.

We can also query these JSON "rows" (different JSON documents) by submitting another JSON with different keys and their corresponding values, and the website will show all rows that matches the key-value pairs that are specified in this JSON (for the provided username, of course).

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

IMAGE OF SEARCH

IMAGE OF NPM

Well, well, well. What could this be?

> Affected versions of this package are vulnerable to Internal Property Tampering. taffy sets an internal index for each data item in its DB. However, it is found that the internal index can be forged by adding additional properties into user-input. If an index is found in the query, taffyDB will ignore other query conditions and directly return the indexed data item. Moreover, the internal index is in an easily-guessable format (e.g. T000002R000001). As such, attackers can use this vulnerability to access any data items in the DB and exploit an SQL Injection.

Amazing. It looks like all we have to query for is the ID of the first element, which is always the same, and a property called `___s`.

## Step 3: Running the exploit

Let's try the provided exploit.

IMAGE

Invalid JSON? Right, because `true` is not a string. Let's change it to `"true"` (filled strings evaluate to true):

IMAGE FLAG

And there's our flag.

You can also see that IDs are easily guessable by simply submitting a bunch of data items under your username.

IMAGE

The IDs are sequential, so it's trivial to find the ID of the flag.