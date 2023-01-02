---
layout: post
current: post
cover: assets/nite/classics/cover.png
navigation: True
title: "Revisiting Classics"
date: 2022-12-27 10:00:00
tags: [niteCTF, forensics]
class: post-template
subclass: 'post'
author: smsliman
---

Paging Nick Gebo - Get Your Ass In Here

We start with a PCAP file. Let's throw it in Wireshark:

![PCAP in wireshark](/assets/nite/classics/img1.png)

We can start by taking a look at the protocol hierarchy.

![protocol hierarchy in wireshark](/assets/nite/classics/img2.png)

It's all TCP, so let's go ahead and follow the TCP stream. For the sake of convenience, we'll only look at the server response.

![TCP server response in wireshark](/assets/nite/classics/img3.png)

Scrolling to the bottom, we find most of the flag. We can definitely see the start, and that seems like the end too, but it looks like there's some more information in the middle there. There are some clear patterns, but no indication of how we might decode it. Luckily, we know one other piece of information: 

![another section of the TCP server response in wireshark](/assets/nite/classics/img4.png)

"RS Cube" and "This is an MC Classic server written in Rust" are [enough to help us find the code for the server.](https://github.com/Skryptonyte/RSCube) Using this, we can spin up our own instance of the server, provide the client input to it, and see what sort of response we get.

![screenshot of text file output from the server, showing lots of block placements](/assets/nite/classics/img5.png)

We can see that all of that junk in the middle was actually block placements. Now we're getting somewhere interesting. We can reformat that data into commands, then open up Minecraft and run them. Doing that, we get this:

![screenshot of minecraft, showing garbled text spelled out with gold blocks](/assets/nite/classics/img7.png)

That's ... something. It seems like it could maybe be our missing section if we clean it up a bit. So I did a little bit of mining off camera, and now we have this:

![screenshot of minecraft, showing middle part of flag spelled out with gold blocks](/assets/nite/classics/img8.png)

That gives us the middle part of the flag, and now we can put all the parts together to get the solution.