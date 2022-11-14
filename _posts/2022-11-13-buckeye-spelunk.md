---
layout: post
current: post
cover: assets/buckeye/honeyedfox/cover.png
navigation: True
title: "spelunk"
date: 2022-11-13 10:00:00
tags: [BuckeyeCTF, misc]
class: post-template
subclass: 'post'
author: honeyedfox
---

All of these challenges are too hard for me. Wait... is that Minecraft???

Last weekend, I got to participate in BuckeyeCTF as an official member of squ1rrel! It was my very first time ever ctf'ing, let alone delving into any type of code or anything similar. Honestly, it was pretty overwhelming, as a lot of the challenges were pretty math or computer science heavy, and my skills lie mostly in the OSINT world, but I still managed to get this flag all on my own! Let's see how a non-cs major tackles "Spelunk!" 

## The hint:

> I wrote the flag on a sign [somewhere](https://drive.google.com/file/d/1R_YzJK7QXt7NZarjpXJKq-LwGX-_kQ7e/view), but I lost it. Only a REAL spelunker can find it!

The link goes to Google Drive with a file called spelunk.zip!

Let’s unzip it!

## The File!
><details ><summary>🗀 Spelunk</summary>
><details ><summary>&emsp;⤷🗀 World</summary>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 advancements</div>
><details><summary>&emsp;&emsp;&emsp;⤷🗀 <mark>data</mark></summary>
><div>&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;⤷ no files found!</div>
></details>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 datapacks</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 DIM1</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 DIM-1</div>
><details><summary>&emsp;&emsp;&emsp;⤷🗀 <mark>playerdata</mark></summary>
><div>&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;⤷ no files found!</div>
></details>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 poi</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 region</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗀 stats</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🖻 icon</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 <mark>level.dat</mark></div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 level.dat_old</div>

Cool! What does any of this mean? I've gone ahead and highlighted the folders and files that'll probably help us the most.
> It'll be important to know later on that the
`level.dat` file refers to the actual world and `level.dat_old` is a backup. (thanks Google)


Good start, right? Only... They're all empty! What else did I expect? Can't be that easy.

Clicking through the rest of the files, we find that only the poi and region folders were left intact. Everything else was wiped!
According to the [minecraft wiki](https://minecraft.fandom.com/wiki/Java_Edition_level_format), **poi** is points of interest and villager stuff, and **region** contains region files, including information on chunks and what's in them. Bingo!

Since we're looking for a flag, there has to be some way to just... search the world, right? It's not like they could've generated that many chunks, right? Let's check.

><details><summary>🗀 Region</summary>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.0.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.1.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.-1.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.2.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.-2.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.X.X.mca...</div>
></details>

What the hell is a `.mca` file?  Why are there so many of them? Oh no.
One more google search later, I quickly learned that all of minecraft's data files are in a propiertry file format called NBT (**n**amed **b**inary **t**ag) and that the best way to edit them is using a program called [NBTExplorer.](https://www.minecraftforum.net/forums/mapping-and-modding-java-edition/minecraft-tools/1262665-nbtexplorer-nbt-editor-for-windows-and-mac)

One quick ~~sketchy~~ download later, we're greeted with this wonderful page.

![](https://lh5.googleusercontent.com/h3gsmfPUv3SS8ThMkPL0gBIf_pTzWqSrltWrkODBJ3Fsj2KBgidlVplllUL_5QeE7_jejDJIWFGNLmuntLN8eHUwmSMBDKaUjby4KID4UWKYiKQtRtDRiM9FmQYnUG5umpZW4XiewwOkpCM3cblYiQ7u8p5xzVrLGMxg7_7CgqfWnsxgiAlXyQqRASGUMw)

Hmm. Well, maybe there's more info now! Let's go back to the region file.

Let’s click it. 

![](https://lh6.googleusercontent.com/GkjCtyWWuAucsxAnytTruAHhpQk-Ziqp_mBtgVHzjR9EQJRpGfh64T1q_zX2b7UPVwGfORw59I7dA3X1QMrOk4G01DCCj937nU6uC4DHMTufopu7hs3HXZB9rm0ioTvEoJCRxLHmXddMewec0c5cl3F3bKLKMDkjt4gl6npUQL-N7cdg8Xis1w7ctaTEmQ)

Seems about right.

![](https://lh6.googleusercontent.com/DLLdaYr0mPrDeGPSnyWP3etI6QZAtG_1GT-SVlSknKqEmHHEjMSd4ujib9X9KCcq5_9pfvCcr7VOHb59y8B4LBZiWX63vrnm0I6BP7LoAOgo4QhTIabHUIeDU7Uiw7JfW0f_F-hNroLu4YUBGGixaGyFLvA2KckQuxU1fdqOmFia0aqkDe126MxkVNOgNw)

Oh no. I've severely underestimated the amount of spelunking I've gotten myself into.

There’s got to be an easier way to do this, right?

That spyglass icon looks interesting.🤔

![](https://lh6.googleusercontent.com/NYhtpKQ-utZFuTigsGbpDZDrJr-czax0ZRpBjgayvsLb83vSWPYR0apj8-1gtr-UhtyXz6x6GGtsIthOmYk_jtsIcy0T7Av6GP75DR_3BZtp7xmujn2T8XEmThvC9AibkI1F9zmOyrJSZsioH2tiqsgZBR_RwShwlQrlFLkPnNAjUqIl3_r5PwJv5w7IJA)

Ah. What do I search? ... Ah, yeah, the flag.  “Buckeye{“ should work, yeah? Layman’s version of find()

![](https://lh3.googleusercontent.com/1app8jK12p1y8KTSvWx7icWYfuObFjT0mA1qLMPo5n_duvs3jd-YTM1jAFS8Kq634YBGnow0NbRw4XFYoHcu0wp_mbE3s41ND1SWqAGrkLuxsDv7-YNGXzwIgzmJ2v_qsBQkqT3rv8HIdCV-ylIlLSn4No4TjxjbW7Tuin9NARhQA6u-Ux84U-UG5nwmsw)

This might take a while.

  

![](https://lh6.googleusercontent.com/RzB8cHjWve_Poza1VgxkA-Pf-__RhZNUpjcxT_3FiE6KPjLgAxYCdgAMcGXNhdYrQZAAYUfDGRSgSwuKFZl33YUSOf80emrZMfGXYtb8ancrkA2fpHOajig81414HMODYMlbK8E65C4F52mfcIFA3WCp3r4cX1pvlX6RYZUbxVAeslLipe-MO5oBZVTHGw)

No results. Damn. What now? Let’s check the world data.

![](https://lh3.googleusercontent.com/1pxfgMptF-o5hwtWp-2OKpqbMgS-3KYxLQ3HW9-eO6D_Tv8X0-Wn260vLR8pU-tmgvEB0fLlnJqQnjXK3MnMJlTUtZ4w3t-sdq_tzE8WTVBXBQY2FG1xQUL5nwBKoYGMOom8rHwIssgce4DQfCazSuDTehiyo95IQghZ-ydjQyVdAqpTsf6PoJL2n2WgFw)

Oh, playerdata! I knew the world file would be important! 

![](https://lh5.googleusercontent.com/d5n7aASaMquvt_31YwFGzeFJ8chFAQ9fNed5hPxuLz20LQAyaSPv9dMJin-qu9UTNw2QYmcDGzeJDSTz4pnkhCTqZCbGIUGSh-5LpWsoZVcWBgrYx7KAp5KTQfiKnO7nyHndUuC-z4zH5OIdypdaRdd55kRYuiJ_FVGycilp4sdGvNV2oGAYttHCDmCDLA)

Position? Maybe they logged out right after placing the flag.

![](https://lh4.googleusercontent.com/cYBUETJ8Ml2A5pB4dK2YwNBR0ZcUx7nIMTZmn7qtPxw3X7ats_PeGaMunoYT9lBDhW4sHAsuLpXH7ahsOl7GqGqndG8990Jrx5uNiagAKMdmdm3gIJwrGBNYd5eg5Mc4x96FUVe8ad5SGE3K--J6qwlhETFJkbVe82WMDw2P6cBsRKpnMLDZvoLB7jxpVA)

Ah. Seems to be spawn. Huh. What now?

At this point, I switched gears. If I wasn't going to be able to find it in the files, I might be able to use a world editor, right? What's the one I always see the YouTubers using? [MCEdit?](https://www.mcedit.net/) 

I then spent 20 minutes installing and troubleshooting MCEdit and browsing Reddit, only to learn that MCEdit doesn't work for worlds above 1.12. Crap. However, that insightful Reddit post also linked another world editor, called [Amulet](https://www.amuletmc.com/). Thanks Reddit!

Once that was up and running, I realized I couldn't search the world for a signpost, and if I could, it would take hours. Ugh. There had to be a simpler way to do this, right?

I went back to the files.

**![](https://lh3.googleusercontent.com/RDAd340yJk7z0qPcSSU3yYd5G9DZ8x62eEJcwqHYIoH00aDcSrDCMn1HPmK-0Wb-wTMNn9gWc0xvG4k5Vh_K3Ph0Sy28qEvrvZSNzC8kFEgvm1fK6m9HwxxnIc7y4EwzEVbn1EPlhU82lLZBpNL3_YMWOo-A2Kse4vJG5UsQmz8ROuasuqtx5djjbVv9zw)**
I'm showing you a screenshot this time for a reason. Look at the times! They're important now. 
Sorting region by size seemed to be useless. There were too many reasons one region might be bigger than the other, but by date? Most of the regions were generated by on 09/25/22, but only a few had been updated after that date. 

Well, it obviously had to be able to be found in the region folder somewhere. I tried sorting them by size. Unfortunately, in both POI and Regions had different files sorted as biggest, so that wasn’t going to help. 

><details><summary>🗀 Region</summary>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.0.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.-1.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.-1.0.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.1.-4.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.1.-5.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.2.-4.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.2.-5.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.-3.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.-4.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.0.-5.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.1.-3.mca</div>
><div>&emsp;&emsp;&emsp;&emsp;⤷🗋 r.2.-3.mca</div>
></details>

Damn. Still too many. Well, if time is important, maybe there's something in the backup world file? Back to NBTExplorer!

**![](https://lh4.googleusercontent.com/hKPqoThjtEt88mVB1-rP8-Jmwg9NVcYHkm53wzl_2otosCviCc2HoVi7h2eiQ61gRRk_LE8YdyEOFP6U9Av6LbjOObvEF-B1F0zHHSJKXu4k5P85dn-482t6aWf8TB_clC_ileoKql64azhewEisooerrgaUG5SaRQWoJzXlztn_2U0mtDDRgeOYVl-Gkg)**

pog. Maybe Amulet will finally have a use and let me see the flag?

**![](https://lh3.googleusercontent.com/4tNLkTdm7AakQvgRW56ETx15pJuv5tefY_U1VWk9MsnKM1zZ-QjqzysTKed9X6zOb7W3pSM1e1N3GSDrKw8TgwC4IAcDZL4u5xsveQgTx_vywa6XwPtrXoi2GWRGV8GM-Wd2xlCll_7D4DS5qE8kBC4TrVgrD1qyBiePgZZBDuKa5cpRjCTrTOy1YfNmuA)**

malding. At least we know the actual flag is there. Let's boot up Minecraft, download the proper version (1.14.2) and... 

**![](https://lh3.googleusercontent.com/8cDbyrLAFScdQ2Q0zkr8mkGYzDta1nGOvxi7rNaCBSgahcqomrpKSEb7XQHyVcDaK_b1uprThe14V_VKHTO2rXiBWFSN0OeWMgVvjSaEPG8icQ4PvD5So20UD8kou2mGlHAp5NrK5aJnT3D_LUSgUqg2eONAFddv1D0NCiBfY_oka3FTGqgA8XX9fXwrgg)**

Wait, shit, how do I give myself creative? StackExchange please don't fail me now I'm too close

**![](https://lh5.googleusercontent.com/WtUy7dWVToy0Zxw0AG76c_sKyT0X2kl0VRl4Jn845NTXyem-zFUKQOSV_375LC4_xGTgy2BycD-DYtbUQfOqFayVKZmkBtJHPdeelezU_3FdLmZkd-tm7a8TS7-bbxVsLrw8JrgF73XEHuDNjC-KQWwKWAaSvn4tcD-BNncDnAv7ePeu6tChoXHnGSMh9A)**

I love StackExchange. I used the Open to LAN method. And one `/tp` later:

**![](https://lh6.googleusercontent.com/SBrYxqHOxZF_E4gjRUoq_I2XiiWeA18xBdzgyQraqW41pio3a9WXROb71dyMNKdYJnq180jgvyEFaopCW_9uwpiUB5XwCD574Dj6GSarS8GhjQd4nHc5s2eDhNnXLmItIOWooNJxGHtDQA66ql-JDQV3f9ywl6AslI5UXTROoIQMnAjQxe1EQCc8TUkdyA)**

ez dubs, gg no re!