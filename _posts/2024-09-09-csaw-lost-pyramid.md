---
layout: post
current: post
cover:  assets/csaw/kyleburgess2025/pyramid_token.webp
navigation: True
title: "Lost Pyramid"
date: 2024-09-09 11:59:00
tags: [csaw, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

The only way to avoid SSTIs is to use protection.

## The Problem

In this problem, we are able to navigate through a pyramid through a website. The goal is to access the King's Lair without being turned away by the king. The king will only allow you in if your JWT token (stored in a cookie) states that you are royalty and that you are approaching on the King's Day.

![A photo of the inside of a pyramid.](/assets/csaw/kyleburgess2025/pyramid.webp)
*This 1000 sqft ranch-style home has an open floor plan, unique architecture, and whispering coming from the walls!*

Lovely. There are a few other rooms, the most notable of which allows you to provide your name, which is then rendered on the screen. Suspicious...

![A photo of a pyramid with text across the top.](/assets/csaw/kyleburgess2025/scarab.webp)
*This seems normal. I'm sure this has nothing to do with the challenge.*

## My Approach

Approaching this problem, I was thinking about 1 think and 1 thing only: JWTs, or JSON Web Tokens. JWTs are a way to securely send information from one place to another. A JWT contains a header (containing metadata about the token), a payload (containing the information that needs to be sent), and a signature (the result of signing the base64-encoded header and payload with a secret key and an algorithm specificed in the header). All this is cool and all, but how can we find a vulnerability here? Akash pointed out that the version of PyJWT specified in the `requirements.txt`, `2.3.0`, has a known vulnerability, described [here](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24). 


In Lost Pyramid, we have a private key and a public key for signing and verifying JWT tokens. The private key is, surprisingly, private, and is used to sign the token; the public key is used to verify that the private key was used to sign the token and therefore verify that the token was sent by someone we trust. What if, and hear me out, we trick the JWT decoder into thinking we are using a symmetric algorithm, which only requires one key? Then, we could sign the token with the public key, and it will be decoded also with the public key. This would be bad, since the public key is, well, public. That's where the vulnerability comes in. 

Basically, if you set `algorithms=jwt.algorithms.get_default_algorithms()` while decoding a JWT, the JWT decoder will try multiple algorithms to decode your JWT. A bad actor can use the symmetric `HS256` algorithm to sign the token with the public key, rather than the intended shared private key. By not specifying the exact algorithm we are using to decode the JWT, the decoder is tricked into thinking the key was signed with a shared private key, rather than a public key, and the decoding is successful. So, rather than needing to know the private key in order to sign the JWT token using the `EdDSA` algorithm used elsewhere in the app, we can sign our key using the public key without any problems. Done. Easy.

Except... we're not done. First off, we don't know the public key. Second off, we don't know the King's Day, which we need to include in our payload. That's where SSTI comes in. SSTI stands for server-side template injection; basically, we can expose variables from the code by injecting our own code. I actually couldn't figure this out for a while until I called fellow teammate Nisala Kalupahana, who calmly and nicely pointed out these lines of code:

{% raw %}

```python
kings_safelist = ['{','}', '𓁹', '𓆣','𓀀', '𓀁', '𓀂', '𓀃', '𓀄', '𓀅', '𓀆', '𓀇', '𓀈', '𓀉', '𓀊', 
                    '𓀐', '𓀑', '𓀒', '𓀓', '𓀔', '𓀕', '𓀖', '𓀗', '𓀘', '𓀙', '𓀚', '𓀛', '𓀜', '𓀝', '𓀞', '𓀟',
                    '𓀠', '𓀡', '𓀢', '𓀣', '𓀤', '𓀥', '𓀦', '𓀧', '𓀨', '𓀩', '𓀪', '𓀫', '𓀬', '𓀭', '𓀮', '𓀯',
                    '𓀰', '𓀱', '𓀲', '𓀳', '𓀴', '𓀵', '𓀶', '𓀷', '𓀸', '𓀹', '𓀺', '𓀻']  

name = ''.join([char for char in name if char.isalnum() or char in kings_safelist])
```

and 

```python
return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    ...
    <body>
        <a href="{{ url_for('hallway') }}" class="return-link">RETURN</a>
        
        {% if name %}
            <h1>𓁹𓁹𓁹 Welcome to the Scarab Room, '''+ name + ''' 𓁹𓁹𓁹</h1>
        {% endif %}
        
    </body>
    </html>
''', name=name, **globals()) # ok nisala yelled at us for missing this
```

Do you see that? `**globals()`. This passes all global variables into the context of the template. Do you see that other thing? Brackets are on the allowlist! Ok, fine, Nisala yelled at us for missing this. Apparently, we hosted a workshop where we discussed this exact vulnerability. Sadly, I host a lot of different workshops on a lot of different topics and also I'm a silly goose so I'm not sure how I was expected to remember all this. Whatever. We keep grinding. Both the King's Day and the public key are stored in global variables, so let's pull those out by claiming our name is `{{PUBLICKEY}}` and `{{KINGSDAY}}`:

Payload: `{{KINGSDAY}}𓁹{{PUBLICKEY}}`:

{% endraw %}

Result:
![A photo of the inside of a pyramid with the public key and the kingsday written on it.](/assets/csaw/kyleburgess2025/scarab_key.webp)
*What a beautiful name for a baby boy.*

Ok, let's put it all together. I wrote this lovely encoding function that created the token we need:

```python
PUBLICKEY= b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPIeM72Nlr8Hh6D1GarhZ/DCPRCR1sOXLWVTrUZP9aw2'
def encode():
    payload = {
        "ROLE": "royalty",
        "CURRENT_DATE": f"03_07_1341_BC",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365*3000))
    }
    token = jwt.encode(payload, PUBLICKEY, algorithm="HS256")

    return token
```

I set the `pyramid` cookie to be equal to this token and proceeded to the King's Lair:

![Gold! Gold!!!](/assets/csaw/kyleburgess2025/pyramid_flag.webp)

Done. QED. Bam.