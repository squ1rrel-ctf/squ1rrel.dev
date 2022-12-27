---
layout: post
current: post
cover:  assets/buckeye/nisala/cover.webp
navigation: True
title: "devil"
date: 2022-11-10 10:00:00
tags: [BuckeyeCTF, misc]
class: post-template
subclass: 'post'
author: nisala
---

I can sorta do CTF problems -- but deep down, I'm a DevOps guy.

So a challenge where I get to run a bunch of Linux tools in a VM to get a result is kinda my dream come true.

## Figuring Out The Challenge

The challenge is named `devil`, and when you connect to it, it gives you a 75 second CAN bus capture 
that looks something like this:

```
...
(1.4393682479858398) can1 0CF00203#C00000FFF7000003
(1.4413127899169922) can1 18FEF000#FFFFFFE015FFFFFF
(1.443253993988037) can1 0CF00C03#00FB0000FFFFFFFF
(1.4451885223388672) can1 18F00E00#FFFFFFFFFFFFFFFF
(1.4471545219421387) can1 18F00503#7D00007D4E204E43
(1.4490914344787598) can1 18FE4A03#035F4FFFFFF3FFFF
(1.4511189460754395) can1 18FE5600#9735FFFF1F1F00FF
```

At the end of the output, the server asks us what the High-Res Max Speed is of the truck 
this data is from.

Now, through sheer luck, I've worked with CAN data before. I actually reverse
engineered the REV Robotics motor controller CAN protocol with Akash (another person on our team!) 
to make it run on ROS2 (Robotics Operating System) instead of being vendor-locked to
FIRST Robotics software last year. So I recognized this right away as a `candump`-type file. Here's the format:

```
(timestamp) CAN_BUS_ID CAN_DEVICE_ID#DATA
```

You'll notice that there's a device ID here, and that it changes. That's because we're not dealing with a single device here,
but instead a *network* of devices (engine, brakes, sensors, etc.), all daisy-chained over CAN. Each device has its 
own ID and way of encoding data specific to it. So we need to find a tool that can decode this device-specific data 
to get the statistic we need.

## Finding the Right Tools

The challenge [has a link to a master's thesis from University of Colorado](https://www.engr.colostate.edu/~jdaily/J1939/candata.html),
which has a [link to tools that can be used to analyze truck CAN data](https://www.engr.colostate.edu/~jdaily/J1939/tools.html). There's
two tools of note here: `pretty_j1939` and TruckCape. 

Let's start with `pretty_j1939`: a tool that can read CAN data and decode it. Sounds pretty straightforward. And it's
made by the National Motor Freight Traffic Association, so it'll probably be good for truck data! However, remember, every CAN
device encodes data in a different way, and there are a ton of different devices out there. So the tool needs a database of devices
and encodings. Some tools come with this data, but this tool in particular uses the **J1939** database -- but this database... isn't free. 
[To get it from SAE, it costs $270.](https://www.sae.org/standards/content/j1939da_201907/) [To get it from CSS Electronics, it costs 500 euros!](https://www.csselectronics.com/products/j1939-dbc-file) 

So can we get a bootleg copy of J1939 from somewhere? For this, I turned to TruckCape. [This repo has a J1939 database in it](https://github.com/SystemsCyber/TruckCapeProjects/blob/master/Jupyter/J1939db.json), and the University of Colorado website promised that it should have everything I need for trucks! However, putting this database into `pretty_j1939` didn't work. The file didn't have enough data. [I also found a more extensive database file](https://www.wheelodex.org/projects/turp1210/) from the university, but that also wasn't enough.

Honestly, I kind of wanted to buy the database at this point. (They said they had free returns after a week, so... could that be the solution?) However, after a nudge in the right direction from the challenge author, I found [TruckDevil](https://github.com/LittleBlondeDevil/TruckDevil/), which matches the challenge name (devil, anyone?) and has a built-in J1939 database. And when you search through the database, guess what encoding you find?

```json
...
"spn": 6808,
"spnName": "Maximum Vehicle Speed Limit (High Resolution)",
...
```

This is the metric we're looking for. Let's get this going.

## Using TruckDevil

TruckDevil is designed to interface with running CAN devices. We don't have that; we only have a dump file. 
However, `candump` is part of a software suite called `can-utils`, which also includes `canplayer`, which can replay CAN dumps! 
So we can use `canplayer` to replay the dump file, and TruckDevil to decode it.

Replaying also requires the creation of a virtual CAN interface, so to avoid messing with my current setup, I spun up an Ubuntu 20 VM. Here's how I set it up:

```bash
# unprocessed candump file is saved as can.log
# install can-utils and kernel modules for vcan
sudo apt update
sudo apt install can-utils
sudo apt install install -y linux-modules-extra-$(uname -r)
# Create vcan0 interface with SocketCAN
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Now, if we try to `canreplay` the file, we get an error:

```
# canplayer -I can.log vcan0
write-if interface name 'can1' is wrong!
```

Right, because our interface is `vcan0`, not `can1`. So let's modify that:

```
# canplayer vcan0=can1 -I can.log
timestamp format in logfile requires 6 decimal places
```

Right, the timestamp is too accurate. I wrote a Python script to quickly fix this up:

```py
with open("can.log") as f:
    lines = f.readlines()

nlines = []
for line in lines:
    time, device, data = line.split(" ")
    time = float(time[1:-1])
    nlines.append("({:.6f}) vcan0 {}".format(time, data))

with open("can-formatted.log", "w") as f:
    f.write("".join(nlines))
```

And now we have a fully formatted file at `can-formatted.log`! Playing that file:

```
# In one terminal: canplayer -I can-formatted.log
# In another terminal: candump vcan0
...
vcan0  0CF00400   [8]  5E 7D B8 4B 05 00 0F AB
vcan0  0CF00203   [8]  C0 00 00 FF F7 FE 00 03
vcan0  18FEDF00   [8]  7D A0 28 7D 7D FF FF F0
vcan0  0CF00300   [8]  D1 00 7F FF FF 0F 72 7D
vcan0  0CF00203   [8]  C0 00 00 FF F7 FE 00 03
vcan0  0CF00A00   [8]  00 00 45 02 FF FF FF FF
vcan0  0CF00C03   [8]  70 06 F4 04 FF FF FF FF
...
```

Looks like we have data streaming over the device! Now, it's time to set up TruckDevil to read this data. This requires Python 3.9, so we'll use Miniconda for that (see what I mean about a DevOps challenge? I dream about CTF challenges like this).

```bash
# conda setup
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
sh Miniconda3-latest-Linux-x86_64.sh
source .bashrc
conda create -n py39 python=3.9
conda activate py39

# Set up TruckDevil
git clone https://github.com/LittleBlondeDevil/TruckDevil.git
cd TruckDevil
python3 setup.py install
cd truckdevil
python3 truckdevil.py
```

And now we're presented with a command line:
```
Welcome to the truckdevil framework. Type 'help or ?' for a list of commands.
(truckdevil) 
```

Awesome. Let's set this thing up. First, let's connect it to the virtual CAN interface:

```
add_device socketcan vcan0 0
```

This sets up vcan0 as a SocketCAN device, with a baud rate of 0 (auto detection). And now, let's go to the `read_messages` module:

```
run_module read_messages
```

Now, it's time to set some settings to set up decoding.

```
set log_to_file true
set log_name data_log.txt
set verbose true # this enables printing of decoded messages
```

And now, we can start reading messages. In this terminal, I ran `print_messages`, and in the other terminal, I ran `canplayer -I can-formatted.log`. And now there's a ton of data scrolling past on the first terminal. We don't need to worry about reading it now, since it's all getting logged. All we have to do is wait until the messages stop, which should take around 75 seconds. Then, we can Ctrl-C out of TruckDevil.

Once that's done, we can download the log file and look for high-res max speed of the truck. And here it is! 

```
SPN(6808): Maximum Vehicle Speed Limit (High Resolution)
104.61 km/h
```

Giving that speed to the server gets us the flag: `buckeye{vr0000m_vr0000m_vr000000m}`