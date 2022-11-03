---
layout: post
current: post
cover:  False
navigation: True
title: "Issues: Another JWT Challenge"
date: 2022-11-02 10:00:00
tags: [SekaiCTF, web]
class: post-template
subclass: 'post'
author: nisala
---

Oh, JWTs. A well-intentioned standard, for sure -- but my god, the number of implementation mistakes you can make.

From leaking secrets to using an unverified header for information, there are a lot of ways to mess up and create a security vulnerability. So let's see what the *issue* was in this challenge.

## The Challenge

In this challenge, we're presented with a very basic web server. The web server has a `/api/flag` route (in `api.py`) that returns the flag:

```py
@api.route("/flag")
def flag():
    return secret_flag
```

Seems simple enough. However, in order to make a request on `/api/*`, you have to be authorized, with a function that checks a JWT token like this:

```py
def get_public_key_url(token):
    is_valid_issuer = lambda issuer: urlparse(issuer).netloc == valid_issuer_domain

    header = jwt.get_unverified_header(token)
    if "issuer" not in header:
        raise Exception("issuer not found in JWT header")
    token_issuer = header["issuer"]

    if not is_valid_issuer(token_issuer):
        raise Exception(
            "Invalid issuer netloc: {issuer}. Should be: {valid_issuer}".format(
                issuer=urlparse(token_issuer).netloc, valid_issuer=valid_issuer_domain
            )
        )

    pubkey_url = "{host}/.well-known/jwks.json".format(host=token_issuer)
    return pubkey_url

def get_public_key(url):
    resp = requests.get(url)
    resp = resp.json()
    key = resp["keys"][0]["x5c"][0]
    return key

def has_valid_alg(token):
    header = jwt.get_unverified_header(token)
    algo = header["alg"]
    return algo == valid_algo

def authorize_request(token):
    pubkey_url = get_public_key_url(token)
    if has_valid_alg(token) is False:
        raise Exception("Invalid algorithm. Only {valid_algo} allowed.".format(valid_algo=valid_algo))

    pubkey = get_public_key(pubkey_url)
    pubkey = "-----BEGIN PUBLIC KEY-----\n{pubkey}\n-----END PUBLIC KEY-----".format(pubkey=pubkey).encode()
    decoded_token = jwt.decode(token, pubkey, algorithms=["RS256"])
    if "user" not in decoded_token:
        raise Exception("user claim missing")
    if decoded_token["user"] == "admin":
        return True

    return False
```

So right away, there's something that's very clearly suspicious -- the public key to verify the JWT's signature is fetched using a web request, based on a URL *in the JWT itself.* Now, what's a public key doing here in the first place?

### A quick aside on JWTs

JWTs, or JSON Web Tokens, have three segments. The first is the header, which defines the algorithm the JWT is signed with. The second is the data, which is arbitrary encoded data that defines attributes about the user (for example, if it's an admin). The third, and most important, is the signature -- it takes the header and data and signs it based on the algorithm. In this case, the algorithm is RS256, which is an asymmetric algorithm that uses a private key to sign the token and a public key to verify the signature.

And now, back to the challenge.

## Challenge Analysis

Now, most challenges ask you to break a part of the JWT implementation itself. Maybe it's reading the header wrong. Maybe you can change the algorithm (if you can change RS256 to HS256, you can create a token with the public key, which we have, and it'll work -- or you can just remove the signature automatically). Maybe you can bypass token verification. But in this challenge, all of this is airtight. We can't create a fake token with the public-private keypair that they have.

So what do we do? Well, it's making a web request to get the public key based on a URL in the token -- so if we can give it a public key URL that we control the private key for, we can make our own tokens! Now, this seems difficult at first glance. The code ensures that the domain the key is at matches the host (`os.getenv("HOST")`). However, there's a route in `app.py` that we can use:

```py
@app.route("/logout")
def logout():
    session.clear()
    redirect_uri = request.args.get('redirect', url_for('home'))
    return redirect(redirect_uri)
```

This route will redirect us to any URL we want -- and because Python `requests` follows redirects, it'll load any data we want while looking like it came from the host server!

## The Exploit

Okay, it's time. In order to exploit this vulnerability, I did the following:
- First, I created a web server with a public key I control. In order to do this, I took the public key from [jwt.io](https://jwt.io) and put it in `.well-known/jwks.json` in the same format as the sample code. Then, I ran `python3 -m http.server` to serve the folder, and used `ngrok` to expose it to the internet.

```json
{
    "keys": [
        {
            "alg": "RS256",
            "x5c": [ "KEY" ]
        }
    ]
}
```

- Then, I crafted the issuer URL to do the redirect. Something like `https://sekai-server.something/logout?redirect=https://1cdf-129-59-122-131.ngrok.io`.
- Finally, I used [jwt.io](https://jwt.io) to create a valid token with the `issuer` field set in the header to the following URL. I also set myself to admin in the payload (as required by the authorization code).

And then, I set the resultant JWT in my Authorization header and made the request to `/api/flag` with Postman. And we're in!