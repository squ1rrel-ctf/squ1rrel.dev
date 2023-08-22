---
layout: post
current: post
cover: assets/fakectf/secret-discord/cover.jpg
navigation: True
title: "Secret Discord"
date: 2022-12-06 10:00:00
tags: [FakeCTF, misc]
class: post-template
subclass: 'post'
author: bunnyrabbit022
---

My friend sent me a link to a discord message, but I can’t access the server!

[https://discord.com/channels/1143240372986851338/1143240373871857757/<br>1143247419623100566](https://discord.com/channels/1143240372986851338/1143240373871857757/1143247419623100566)

image.png:
![image1.png](/assets/fakectf/secret-discord/image1.png)

The only thing we have to work with that might point us to a server is a discord message link. The only thing that looks like it's helpful are the numbers in the link, so I googled the structure of a discord message link.

Aha! The number right after channel is probably what we need. "[1143240372986851338](https://discord.com/channels/1143240372986851338/1143240373871857757/1143247419623100566)" is a server id, and the next two are the channel and message id, which we will use later to find the specific message.

Looking at the image that was provided, I see a Discord widget, with a "Join Discord" button at the bottom. If I could somehow recreate this widget for the server, then I’d be able to join. Knowing this, I create my own server, and find my way to the widget screen.

![widget screen](/assets/fakectf/secret-discord/image2.png)

Here we can see the "Premade Widget" code.

```html
<iframe src="https://discord.com/widget?id=123456789&theme=dark" width="350" height="500" allowtransparency="true" frameborder="0" sandbox="allow-popups allow-popups-to-escape-sandbox allow-same-origin allow-scripts"></iframe>
```

The only thing here that seems to identify the server it is a widget of is the server ID, which we had previously found. I take the premade widget code, replace the id with the server id, and run the code!

![widget code](/assets/fakectf/secret-discord/image3.png)

Now the widget pops up in chrome on a blank screen, and I click join Discord, and then I click the message link. There’s the flag!
