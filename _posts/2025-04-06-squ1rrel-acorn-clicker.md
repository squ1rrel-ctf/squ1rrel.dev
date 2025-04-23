---
layout: post
current: post
cover:  assets/squ1rrel/kyleburgess2025/acorn-clicker/cover.webp
navigation: True
title: "Acorn Clicker"
date: 2025-04-06 11:59:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

Click acorns. Buy squirrels. Profit.

Anyone else love getting emails from companies saying they fucked up? It's one of my favorite things ever. So imagine my excitement when I received this email from the company I work at:

![image of email](/assets/squ1rrel/kyleburgess2025/acorn-clicker/email.webp)
*I appreciate the transparency.*

Incorrect deserialization of negative numbers? This was just BEGGING for a challenge to be written about it! So I got to work.

# The Problem

After registering an account, we are brought to the beautiful Acorn Clicker and Squirrel Market...

![image of main page of website](/assets/squ1rrel/kyleburgess2025/acorn-clicker/main.webp)
*What a beautiful website! Compliments to the designer.*

Clicking the acorn gives us a random number of acorns between 1 and 10, and increases our balance accordingly. When we reach 999999999999999999 acorns, we can buy the Flag Squirrel, who holds the flag.

There are two solutions to this challenge.

# Solution 1: Get to clickin'

Assuming we get lucky and get 10 acorns every time, we only have to click 1e17 times to get the flag. Assuming a rate of 8 clicks/second, you can get this done in 3,472,222,222,222 hours, or 396,372,399 days. If you get a few friends involved, you could probably shave this down.

# Solution 2: Achieve a Negative Balance

Let's take a look at the code. First off, in `package.json`, we have something pretty suspicious going on...

```json
{
  "name": "acorn-clicker",
  "version": "1.0.0",
  // ...
  "dependencies": {
    // ...
    "mongodb": "6.13.0"
  },
  "overrides": {
    "mongodb": {
      "bson": "6.10.2"
    }
  }
}
```

Suspicious... using an exact version of Mongo instead of the latest. Also, overriding the version of `bson` being used to be an earlier version... strange...

We can also see something suspicious in `index.js`:

```js
const client = new MongoClient(url, {
  useBigInt64: true,
});
```

Why are we using `useBigInt64`? This causes all Longs to be deserialized as BigInts. Again... very strange...

A bit of research into this specific version of the MongoDB Node driver will turn up [this CVE](), as mentioned in the email. Seems like the balance is the long that will be deserialized as a BigInt, so our next step is to get our balance negative.

The market checks when you purchase a squirrel if you have enough money, so this won't get us flag. However, when you click, the amount you receive is sent from the frontend to the server. The server checks if this value is less than 10, but does not check if it is negative. So... let's boot up our Postman (or Thunder Client, if you're lazy like me) and send a POST request to `/api/click` with the following payload:

```json
{
  "amount": -10 // or whatever amount you need to get your balance negative
}
```

We also need to auth up - you can get your JWT token by running `localStorage.getItem("token")` in your browser console, and set this as Bearer auth in your request. Once the request succeeds, let's see what our balance is:

![a VERY POSITIVE balance](/assets/squ1rrel/kyleburgess2025/acorn-clicker/balance.webp)
*cash money*

HOLY SMOKES! We're loaded! We can now purchase the Flag Squirrel and collect the flag.

Flag: `squ1rrel{1nc0rr3ct_d3s3r1al1zat10n?-1n_MY_m0ng0?}`
