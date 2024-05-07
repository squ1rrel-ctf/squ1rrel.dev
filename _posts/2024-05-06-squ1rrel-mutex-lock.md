---
layout: post
current: post
cover:  assets/squ1rrel/nisala/mutex-lock/cover.webp
navigation: True
title: "Mutex Lock"
date: 2024-05-06 09:59:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: nisala
---

just solved distributed systems

This challenge was the second hardest in web, with ten solves. As I discuss later in this writeup, I wrote this challenge in response to new trends in web security. Backdoored and malicious packages are becoming increasingly common, especially in the npm ecosystem. [Entire companies](https://socket.dev) have been created to help identify these problems, and yet I've never seen a challenge with one in a CTF before. 

## Step 1: Getting our bearings

In this challenge, we're presented with a simple "web mutex" interface. The interface allows us to create and lock a mutex, and unlock it given the pasword we got when we acquired the lock.

![Image of the challenge website](/assets/squ1rrel/nisala/mutex-lock/challenge-site.png)

Now, as far as I can tell, there's nothing exploitable at all in this -- the operations are very simple, and there's nothing nefarious going on. The flag is stored in the env, but there's no way to get to it using this simple web server code.

## Step 2: Finding inconsistencies

However, if you look in the frontend source, you'll see something very curious: a button that takes you to `/flag`. What happens when you go there?

![Browser standard 404 page](/assets/squ1rrel/nisala/mutex-lock/remoteflagnotfound.png)

A "Not Found" page. Boring, right? But what if you go to another URL that shouldn't exist, like `/asdf`?

![Express 404 page](/assets/squ1rrel/nisala/mutex-lock/remoteothernotfound.png)

The 404 page is different... but the `/flag` route isn't in the provided source. What's going on?

Another way to discover this is by running the web server locally. If you download the ZIP file and run `npm install` and then `node index.js`, and go to `localhost:3000/flag`, here's what you see.

![Express 404 page](/assets/squ1rrel/nisala/mutex-lock/localflagnotfound.png)

Okay, something really weird is going on. This is a normal Express 404 page. The tampering is gone!

Clearly, something must've changed in the install step. At this point, there are two ways you might notice what's going on:

1. The `package.json` file has a call to `npm update` in the `preinstall` script, which might be changing the paackages. You can then diff the `package-lock.json` against the one in the ZIP file to see what changed.
2. You might also notice that instead of running `npm install` in the Dockerfile, it runs `npm ci --ignore-scripts`, which would skip the `preinstall` `npm update` step. `ci` also does a clean install, directly from the `package-lock.json`. If you run this locally, the non-normal 404 page shows up. There's definitely something going on with the pacakges, and again, you can diff the `package-lock.json` file to find it, pre- and post-update.

## Step 3: Exploiting the dependency

Diffing `package-lock.json` will show that `express`, despite what `package.json` is telling you, isn't coming from NPM -- it's coming from GitHub. This is an issue with NPM. Typically, when you install a package from GitHub, it'll show you it's from GitHub in `package.json`. However, it isn't *required* to be there to pass validation when doing a clean install. You can replace it with a simple version number, like it would be with an installation from the NPM registry, and as long as the `package-lock.json` is still there, it'll keep silently installing from GitHub. Even `npm audit` won't show that this is secretly happening. *This is a huge issue with npm.*

As an aside, GitHub doesn't even show `package-lock.json` diffs in PRs, calling them "too long". Without some external tool monitoring a project's `package-lock.json`, you could easily slip in your own version of a dependency in a routine PR, and create a backdoor that nobody would notice. Scary stuff, and we're already starting to see high-profile supply-chain attacks like this. I believe this is part of the future of web security and vulnerability analysis, which, again, is what inspired me to write a challenge like this.

Anyways, here's the diff you'll see:

```json
"node_modules/express": {
      "version": "4.19.1",
      "resolved": "git+ssh://git@github.com/nkalupahana/express.git#ce12ff3ac1377b0e5f371a77460b3938ae15d63b",
}
```

If we go to this commit of this repo, what do we find?

![Diff showing modified code in express package](/assets/squ1rrel/nisala/mutex-lock/diff.png)

Without the `pwd` parameter, we get a 404 page. But with it?

![Flag](/assets/squ1rrel/nisala/mutex-lock/flag.png)
