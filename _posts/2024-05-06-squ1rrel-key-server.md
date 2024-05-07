---
layout: post
current: post
cover:  assets/squ1rrel/nisala/key-server/cover.png
navigation: True
title: "Key Server"
date: 2024-05-06 09:58:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: nisala
---

challenge description

## Step 1: Getting our bearings

In this challenge, we're presented with a simple "web mutex" interface, that allows us to create and lock a mutex, and unlock it given the pasword we got when we acquired the lock.

TODO INSERT IMAGE

Now, as far as I can tell, there's nothing exploitable at all in this -- the operations are very simple, and there's nothing nefarious going on. The flag is stored in the env, but there's no way to get to it using this simple web server code.

However, if you look in the frontend source, you'll see something very curious: a button that takes you to `/flag`. What happens when you go there?

TODO IMAGE OF NOT FOUND

A "Not Found" page. Boring, right? But what if you go to another URL that shouldn't exist, like `/asdf`?

TODO IMAGE OF ACTUAL 404 PAGE

The 404 page is different... but the `/flag` route isn't in the provided source. What's going on?

Let's try running the web server locally. If you download the ZIP file and run `npm install` and then `node index.js`, and go to `localhost:3000/flag`, here's what you see.

TOOD IMAGE OF NORMAL 404 PAGE

Okay, something really weird is going on. This is a normal 404 page. The tampering is gone!

Clearly, something must've changed in the install step. At this point, there are two ways you might notice what's going on:

1. The `package.json` file has a call to `npm update` in the `preinstall` script, which might be changing the paackages. You can then diff the `package-lock.json` against the one in the ZIP file to see what changed.
2. You might also notice that instead of running `npm install` in the Dockerfile, it runs `npm install --ignore-scripts`, which would skip the `preinstall` `npm update` step. If you run this locally, the weird 404 page shows up. There's definitely something going on with the pacakges, and again, you can diff the `package-lock.json` file.

Diffing this file will show that `express`, despite what `package.json` is telling you, isn't coming from NPM -- it's coming from GitHub. This is an issue with `package.json`. Although typically, when you install a package from GitHub, the source will show up there, it isn't *required* to pass validation when doing a clean install. You can replace it with a simple version number, like it would be with an installation from the NPM registry, and as long as the `package-lock.json` is still there, it'll keep silently installing from GitHub. Even `npm audit` won't show that this is secretly happening.

```json
"node_modules/express": {
      "version": "4.19.1",
      "resolved": "git+ssh://git@github.com/nkalupahana/express.git#ce12ff3ac1377b0e5f371a77460b3938ae15d63b",
}
```

If we go to this commit of this repo, what do we find?

TODO INSERT DIFF

Without the `pwd` parameter, we get a 404 page. But with it?

TODO INSERT IMAGE OF FLAG