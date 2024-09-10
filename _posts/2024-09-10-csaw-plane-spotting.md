---
layout: post
current: post
cover: assets/csaw/kohrachel/plane_spotting.webp
navigation: True
title: "Russian Jet Tracking"
date: 2024-09-09 11:59:00
tags: [csaw, misc]
class: post-template
subclass: 'post'
author: kohrachel
---

Last Friday night, the little me who aspired to be like those hackers in movies finally had her dreams come true. Or, girl tracks Russian planes.

Right. This was the Plane Spotting challenge, an intermediate OSINT challenge for the CSAW Qualifiers 2024.

## The Problem

> My friend swears he saw a Russian plane in the US this June, but I don't believe him. He also says he saw it was parked next to a plane owned by an infamous former president!
>
> My friend also tells me that a few days earlier, ANOTHER Russian plane flew to the US. Find the city that Russian plane was closest to at 21:07:40 Z during its flight to the US!
>
> Can you find the registration number of this Russian plane, the FAA airport code of where the plane was spotted parked next to the other, as well as the registration number of the plane owned by that president?

## Breaking (it) down 

Let's do what we do best: break down. 

### The first part 

The first part tells us 3 important pieces of information: `June 2024`, `Russian plane in US`, `infamous former president`. Given the fact that this was from NYU, we can infer that the last piece of information is referencing former President Trump. So we look up `trump plane russian june`, and almost immediately this handy link pops up:

[https://onemileatatime.com/news/russian-government-jet-new-york-washington/](https://onemileatatime.com/news/russian-government-jet-new-york-washington/)

Neat. Why can't my homeworks be this easy? Anyway. Thanks to one Ben Schlappig, we know it was on June 26, 2024, the plane registration code was **RA-96019** (and its flight number was RSD738, this will be useful later), and the planes were spotted at Washington Dulles airport (FAA code **IAD**). Google is also kind enough to tell us that Trump's plane had the registration number of **N757AF**.

### There's another one??

> My friend also tells me that a few days earlier, ANOTHER Russian plane flew to the US. Find the city that Russian plane was closest to at 21:07:40 Z during its flight to the US!

For this part, we're gonna need to get a bit more creative. I trial and errored a bit before figuring out that if Russia was gonna jetset around the US in a few days -- and people actually knew about it -- chances were that it was probably the same plane. The previous website also told us that the plane flew from JFK to IAD. So what if they had the same flight codes? 

Googling `"rsd738" jfk to iad flightaware` pulled up the flight summary. We go into the track log, convert UTC to EDT, and arrive at the following coordinates: (40.2214, -74.7175). Putting that into Google Maps yields: `130 Kuser Rd, Hamilton Township, NJ 08619` which is in the city of **Trenton**.

Put it all together, and we get the flag!!!

```
csawctf{RA96019_IAD_N757AF_Trenton}
```

Problem solved, and hacker thirst quenched (or was it?).