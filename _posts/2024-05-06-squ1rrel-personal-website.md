---
layout: post
current: post
cover:  assets/squ1rrel/nisala/personal-website/cover.webp
navigation: True
title: "Personal Website"
date: 2024-05-06 10:00:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: nisala
---

Check out my personal website! I have a blog!

This was the hardest web challenge in the CTF, with only two solves. My favorite part about this challenge is that it kinda "punishes" you for thinking like a CTF player. This challenge doesn't respond well to throwing tools at the problem. Instead, you have to really understand the technology and its shortcomings, and take a methodical approach that's specific to the challenge itself.

## Step 1: Getting our bearings

This challenge has no source, so all we have to go off of is the website, https://blog.squ1rrel.dev.

![Image of the challenge website](/assets/squ1rrel/nisala/personal-website/challenge-site.png)

Let's start by identifying its technologies. Using the Chrome extension Wappalyzer, we can see that the site is hosted on Firebase. I'm not entirely sure how the extension is figuring this out, but there are a number of possibilities, from the IP it's connecting to (an easily-identifiable Firebase load balancer), to the fact that blog.squ1rrel.dev has a CNAME record to a web.app URL (Firebase Hosting's subdomain).

We can also see that the challenge very clearly wants us to look at cloud storage. The blog post only has one image, and it's being loaded in from Firebase storage. The blog post also says they have "more in storage". So, let's do that.

![Storage link in HTML](/assets/squ1rrel/nisala/personal-website/storage.png)

## Step 2: Authentication

There are two layers of authentication in this challenge -- authentication with Firebase as a web app, and authentication with Firebase as a user. Let's start with app authentication.

In order for Firebase to know what app we're referencing, we need to pass it a config, which contains an API key and various access URLs. Thankfully, because this site is hosted on Firebase, that's easy to get. It's always at `https://blog.squ1rrel.dev/__/firebase/init.json` (among other places in these reserved URLs).

```js
const firebaseConfig = {
    "apiKey": "AIzaSyAlUQ9NC6P-KiEVPuwD9X6rwuZwB1lcvd4",
    "authDomain": "my-personal-website-a.firebaseapp.com",
    "databaseURL": "https://my-personal-website-a-default-rtdb.firebaseio.com",
    "messagingSenderId": "415548456803",
    "projectId": "my-personal-website-a",
    "storageBucket": "my-personal-website-a.appspot.com"
};

const app = initializeApp(firebaseConfig);
```

Next, we need to authenticate as a user. If we don't, we'll get "permission denied" errors whenever we try to access storage. To do this, we'll use Firebase authentication. There are three possible non-SSO methods that could be enabled: email and password, anonymous, and phone. Let's try email and password.

```js
const auth = getAuth();
await createUserWithEmailAndPassword(auth, "test@user.com", "password");
```

And we're authenticated!

## Step 3: Storage

Now, it's time to get our files. Firebase Storage does technically have a way to stop users from enumerating the files in a storage bucket, but most people don't configure it. Instead, they just mark the bucket as "read-only", not realizing that "read" permissions also for some reason include "list" permissions. Thus, we can list the files in this bucket.

```js
const storage = getStorage(app);
const data = await list(ref(storage, "/"))
```

And check it out, we have two files: the image on the website, and `database.rules.json`. 

```json
{
  "rules": {
    ".read": false,
    ".write": false,
    "personal": {
      "$uid": {
        "$i": {
          ".write": "auth != null && auth.uid == $uid && newData.val() == root.child('flag').child($i).val()"
        }
      }
    }
  }
}
```

This file is typical of Firebase Realtime Database, and explains how it's secured. It looks like we need to do an "oracle" attack on the database. (This was actually a challenge at a past CTF -- Firefun, at UDCTF. This challenge was inspired by that challenge, although it only required you to do Step 4 below.)

## Step 4: Database Attack

These rules show the flag stored at `/flag` -- but we can't read it! However, we *can* read it by proxy, using the write permission rule in our personal sector of the database. This rule allows us to write a letter to our personal section of the database, if and only if it matches the letter in the flag at the correct position.

```js
import { getDatabase, ref as dbref, set } from "firebase/database";

for (let i = 0; i < flag.length; ++i) {
    const r = dbref(db, `/personal/${uid}/` + i);
    await set(r, flag[i]);
}
```

If the `set` fails, that means we guessed the wrong letter and need to try again. But if it succeeds, the letter is correct and we can move onto the next one.

And with that, we have the flag! `squ1rrel{fIrebas3_hAs_s0me_interesting_qu1rks}`