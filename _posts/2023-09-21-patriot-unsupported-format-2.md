---
layout: post
current: post
cover:  assets/patriot/unsupportedformat2/cover.png
navigation: True
title: "Unsupported Format 2"
date: 2023-09-21 02:00:00
tags: [PatriotCTF, forensics]
class: post-template
subclass: 'post'
author: smsliman
---

>Just a silly little forensics challenge.


Like Unsupported Format 1, we start with a “corrupted” image file. However, opening this file as text, we can see that the corruption is really just the word “CORRUPTED” written a bunch of times. Using find and replace we can easily remove the “CORRUPTED”s and are now able to open the file as an image. This is the exact same trick employed in Unsupported Format 1, so nothing particularly interesting is going on so far.

We then see the Windows background. Wow! What a classic. At this point though, there is nothing immediately obvious to do, so we turn to binwalk.

![binwalk output](/assets/patriot/unsupportedformat2/binwalk.png)


Here we can see there is a zip file hidden in our image. We can extract it using ```binwalk -e``` and unzip the zip file to find another image. Unlike Unsupported Format 1 though, the computer in this image doesn’t have the flag, and just coyly says “Not a Flag”. However, it still feels a little suspicious, so we can throw it in an image editor to see if there is anything strange going on visually.


After messing around with various settings for a while, we can eventually find that increasing the luminance gradient gives the following:

![image of the computer with the luminance gradient increased](/assets/patriot/unsupportedformat2/flag.png)

And with a little bit of zooming in and squinting, now we have our flag.