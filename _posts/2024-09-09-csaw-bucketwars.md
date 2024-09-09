---
layout: post
current: post
cover:  assets/csaw/kyleburgess2025/bucket_knights.webp
navigation: True
title: "BucketWars"
date: 2024-09-09 11:59:00
tags: [csaw, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

The hardest challenge for a CTFer to solve is how to lose their versionity.

## The Problem

No source code? No problem. Let's take a look at this website.

![A webpage with a photo of a bucket and a caption.](/assets/csaw/kyleburgess2025/homepage.png)
*Wow. Very philosophical.*

The BucketWars website is very, very, very simple. We can see a photo of a bucket with some feaux-poetic musings along with a version label. We can also navigate to `/versions` to see a list of previous versions, from `v1` to `v5`. Clicking on the version brings you to `/index_v#.html`, each of which is a slightly different website... nothing of note here. Of course, my pattern-recognizing ass immediately got cheeky with it and tried `/index_v6.html` to see if anything appeared. 

![Just a lousy 404 page.](/assets/csaw/kyleburgess2025/404.png)

Man, just a 404 page... but an INTERESTING 404 page! First off, we can glean that the website is hosted on an AWS S3 bucket somewhere in the cloud. We can tell by the domain name that the bucket name is `bucketwars.ctf.csaw.io`. We also see a link to what should have been the 404 page. Opening the URL gives us this: 

![Three Kermits doing the see no evil hear no evil speak no evil pose.](/assets/csaw/kyleburgess2025/kermit.png)

## Messing Around

As a long-time AWSer, I definitely knew about the cloud shell inside the AWS website and definitely have not just used the CLI this whole time, definitely. I started out by trying to list everything in the bucket... maybe there's a file I don't know about! Sadly, running `aws s3 ls bucketwars.ctf.csaw.io` just gives us a "Not Authorized" error. I tried a few other S3 commands, but couldn't find anything. This is where I lost hope. Dejected, I walked home from the engineering building at 1am to shower and go to bed.

## An Epiphany

As I stood in the shower, I kept repeating to myself, "Versioning... S3... Versioning..." until I eventually hit "woah... S3 versioning!" S3 allows you to enable versioning on your files, which keeps track of all past versions of a file for you. You can see the version history by using the `aws s3api list-object-versions` command. Running `aws s3api list-object-versions --bucket` gave me...

![Versions of files!!!](/assets/csaw/kyleburgess2025/versions.png)

Woah!! I was suddenly able to see all of the previous versions of files. I tested each one by navigating to `https:bucketwars.ctf.csaw.io.s3.amazonaws.com/path/to/file?versionId=VERSION_ID`. A bunch were nonsense, but a few on `index_v1.html` seemed to be leading somewhere, until I reached `https://bucketwars.ctf.csaw.io.s3.amazonaws.com/index_v1.html?versionId=t6G6A20JCaF5nzz6KuJR6Pj1zePOLAdB`:

![A weirdly high-res photo of a bucket.](/assets/csaw/kyleburgess2025/suspicious-bucket.png)
*A weirdly high-res photo of a bucket.*

At first, I thought this was just some more nonsense, but stegonography run by Patryk using Aperi'Solve revealed the flag:

`csawctf{lEaKY_Bu4K3tz_oH_m3_04_mY!}`