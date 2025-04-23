---
layout: post
current: post
cover:  assets/squ1rrel/kyleburgess2025/go-getter/cover.webp
navigation: True
title: "Go Getter"
date: 2025-04-06 11:59:00
tags: [squ1rrel, web]
class: post-template
subclass: 'post'
author: kyleburgess2025
---

There's a joke to be made here about Python eating the GOpher. I'll cook on it and get back to you.

I recently attended the InsomniHack conference with a few other members of the team and heard some absolutely amazing talks. One of them stood out in particular due to my love of Golang and my desire to write a challenge in Go. The talk was titled [Go Parser Footguns](https://insomnihack.ch/talks/go-parser-footguns/) and was presented by Vasco Franco of Trail of Bits fame. The presentation hasn't been posted publicly yet, but I'll link it here once it has. Basically, the talk covered all the strange ways in which Go parses data and how that can really mess you up. There were, like, ten challenges I could've written about this subject but I held back for y'all's sakes... you're welcome ☺️

# The Problem

The challenge itself is very simple. We have a server written in Go that's serving us some HTML. We can either get a GOpher or get the flag. Sadly, simply asking for the flag doesn't work - we are told that only admins can access the flag. 

![image of home page](/assets/squ1rrel/kyleburgess2025/go-getter/gopher.png)
*God, so true! I AM three gopher!*

The website consists of two separate services - the Go service, which serves HTML and authenticates us as an admin, and the Python service, which gets us our GOpher (or the flag). The Go service receives a JSON input from the frontend and checks if the user is attempting to execute the `getgopher` action. If so, it forwards the JSON input to the Python server. If the user is attempting to execute `getflag`, the server checks if the user is admin - this is hardcoded to false, so this always returns an authentication error. The Python server checks if the action is `getgopher` or `getflag`; if it's `getgopher`, it returns a randomly generated gopher. If it's `getflag`, the server returns the flag. The Python server is not accessible outside the network, so requests cannot be made to it by anything outside of the Go server.

The goal, then, is to find a payload that makes the Go server think you are executing the action `getgopher`, but the Python server think you are executing `getflag`. 

The first thing to think about is how Go and Python differ in terms of parsing JSON. First off, Python's JSON parser is case-sensitive, while Go's `json` package is not. Also, both Go and Python have JSON parsers that use the last key. 

Using this information, we can craft a payload that returns `getflag` for the Python JSON parser, and `getgopher` for Go:

```json
{
  "action": "getflag",
  "aCtion": "getgopher"
}
```

Submitting this payload in the body of a POST request to the `/execute` route will get you the flag!

Flag: `squ1rrel{p4rs3r?_1_h4rd1y_kn0w_3r!}`
