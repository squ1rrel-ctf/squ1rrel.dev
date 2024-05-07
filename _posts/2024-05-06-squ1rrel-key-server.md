---
layout: post
current: post
cover:  assets/squ1rrel/nisala/key-server/cover.webp
navigation: True
title: "Key Server"
date: 2024-05-06 09:58:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: nisala
---

Well, my application is finally making it big -- and I've heard that once you get over 10 users, using kubernetes is basically a must. Come check out my microservices!

This challenge is more psychological than anything. With a bit of inspection, it's not too hard to figure out what the vulnerability is -- but figuring out how to actually use it requires you to think outside the box. 31 solves in total.

There's pretty much no frontend to this challenge, so we'll be focusing almost entirely on the code. The site has an `/admin` route, which will give you the flag if you have a satisfactory JWT token. 

```js
const token = req.cookies["token"];
if (!token) {
    return res.status(401).send("Token cookie missing");
}
```

First, your JWT has to be in a cookie called `token`. Simple enough.

```js
try {
    const { header } = jwt.decode(token, { complete: true });
    if (!header?.issuer || !header?.alg) {
        return res.status(401).send("Headers missing");
    }
} catch (e) {
    return res.status(401).send("Failed to decode token");
}

let issuer;
try {
    issuer = new URL(header.issuer);
} catch (e) {
    return res.status(401).send("Failed to parse URL");
}

if (!issuer.host.startsWith("10.")) {
    return res.status(401).send("Invalid IP address");
}
```

Next, your JWT has to have a header called `issuer`. Again, very doable. However, this field is special: it must contain a link to a public key whose private key pair was used to sign the JWT. And there's more: **the host of this URL must start with `10.`**.

All IPs that start with `10.` are private IP addresses, which is where most people doing this challenge get lost. After all, the error message references IP addresses! However, subdomains can also be numbers -- so instead of somehow getting a public key that you control the private key of on the local network of this VM (likely impossible), you can get a subdomain that starts with `10.`. This can be done on a domain you control, or there are many free subdomain services out there. I used my domain: [https://10.nisa.la/key](https://10.nisa.la/key).

If you control the public key and private key, then you control the full contents of the JWT, and the rest of the challenge becomes elementary.

Here's the final setup on `jwt.io`:

![jwt.io setup](/assets/squ1rrel/nisala/key-server/jwt.png)

And with that set, we get the flag. `squ1rrel{subdomains_that_start_with_10_should_be_private_too}`