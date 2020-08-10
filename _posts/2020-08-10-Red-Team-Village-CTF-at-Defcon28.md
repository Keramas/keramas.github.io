---
layout: post
title: 'Red Team Village CTF @ Defcon 28 (Defcon Safemode)'
date: '2020-08-10T00:00:00.000-00:00'
author: Keramas on behalf of all of Neutrino Cannon
tags: [ctf, defcon28, defconsafemode, redteamvillage]
---

While Defcon 28 was fully virtual due to Covid-19 and the fun of physically gathering to meet friends and participate in the myriad of activities Defcon has to offer was lost, this year's Defcon was mindblowingly awesome just due to the sheer amount of content from all of the villages that was generated/provided for free. For myself and Neutrino Cannon, the main focus this year was on the Red Team Village CTF. We have partipicated in several of their CTFs throughout the year, and the one held at DC28 was the culimination of everything--and the Red Team Village went all out creating a high-quality competition which easily became a memorable one for the history books.

Due to the nature of the competition as well as the amount of focus placed on winning, there is no real efficient way to do a complete write-up of the finals; however, it would be a shame not to write something about this CTF as the organizers dedicated what I can only imagine to be countless hours creating something really great. With that said, this blog post will revolve around documenting the CTF from a higher-level view and less about full details about each individual flag. The purpose mainly being to incite motivation for those reading to participate in the next Red Team Village CTF, and to get involved with that community as well! 

<center><img src = "/assets/images/redteamctfdc28/redteamlogo.png"></center>

# Competition Overview

This CTF was divided into several different parts:

- Qualifiers round

This was your traditional jeopardy style CTF which encompasses a variety of topics over nearly 100 or so different challenges. Lasting 24 hours, the top 20 teams at the end of the 24-hour period would move on to the finals round. 

- Reconnaissance round

As the finals involved a simulated red team operation against a corporate network, 24 hours was given to perform reconnaissance on the target via OSINT and other means. 

- Finals round

The finals lasted another 24 hours, and each qualifying team was given a VPN connection in order to attack the target's interal network. The goal was to plunder the network for various flags hidden throughout. 

# Recon Overview

For the sake of brevity and to also focus on the unique aspects of this CTF, I am going to skip over the qualifiers. There are number of write-ups available for past jeopardy-style Red Team Village CTFs, so it shouldn't be too hard to research details if you are interested in that. 

We had 24 hours to gather as much information we could find about our target, Initech (initech.business) and their employees. The organizers chose the classic movie Office Space as the theme, and it made for a really great time with the humor! 

For those new to OSINT and passive target recon prior to actual active breaching and such, this involves scraping usernames/emails from LinkedIn, searching for public code respositories, open cloud storage, and gathering other potentially useful details on employess via social media and other sources.

<img src = "/assets/images/redteamctfdc28/homepage_members.png">

## So you want to be a phone phreak?

Based on the results of recon, Michael Bolton's resume can be found which shows Initech's phone number (which can also be found on their webpage (https://initech.business) in addition to his extension. 

<img src = "/assets/images/redteamctfdc28/michaelresume.png">

Turns out, this number is actually active and in-scope for the competition! Dialing it up, you are presented with a phone tree, and there were lots of flags (and credentials!) hidden here. With some knowledge of the movie, it is possible to retrieve Michael Bolton's password after answering the special passphrase question: "snoop". 

To give an idea of the phone tree structure, the following is a map:

<img src = "/assets/images/redteamctfdc28/phonetree.png">

Generally, each path led to different flags in the form of a recorded message from a very robotic voice. To give an idea, the following is a sample flag:

<audio controls>
  <source src="https://raw.githubusercontent.com/Keramas/keramas.github.io/master/assets/images/redteamctfdc28/phonetree.mp3" type="audio/mp3">
</audio>

It took a combination of listening a million times and guessing in order to submit these flags. 

## Your Git is leaking and your bucket is showing, friend.

Performing searches for Initech/Initech employee-maintained code repositories resulted in the discovery of two different repositories both Samir and Michael.

### Samir - https://gitlab.com/samir.nahanana

Unfortunately for Samir, this repo leaks AWS credentials.

<img src = "/assets/images/redteamctfdc28/samirkeyleak.png">

Using this information, it was then possible to access an Initech AWS S3 bucket which contained several files, including an VPN configuration file.

### Michael - https://github.com/michaelbolton1

This repository had a .tar file which contained source code for what appeared to be an internal application. 

<img src = "/assets/images/redteamctfdc28/michaelrepo.png">

Examining the source code, it is clear that there is a vulnerability present for remote code execution, and this would play a key role in compromising a machine during the finals.

```php
<?php
if ($_SERVER['HTTP_LOGGED_IN'] == True) {
    if (isset($_GET['employee']) && isset($_GET['status'])) {
        $employee = addslashes($_GET['employee']);
        $status = addslashes($_GET['status']);
        shell_exec("echo $status > $employee.status");
    } else {
        echo 'fail';
    }
}
?>
```
# Finals Overview

<img src = "/assets/images/redteamctfdc28/welcome.png">

While a lot of useful data could be retrieved during the recon phase, the main goal was to obtain the OpenVPN file from the S3 bucket in order to access the internal network. Naturally, since this is a competition and each team received their own dedicated lab instance, the discovered VPN file was incomplete, and at the start of the finals, team captains were provided an updated file.

Once accessing the internal network via VPN, your standard network enumeration was performed for host discovery and services using tools like Nmap, CrackMapExec, etc. In the end, the following subnets were accessed, many through pivoting due to segmentation.

- 10.0.10.0
- 10.0.20.0
- 10.0.30.0
- 10.0.40.0
- 10.0.50.0
- 10.0.60.0
- 10.0.70.0

## Exploit, pillage, and plunder

The 10.0.10.0/24 had a variety of web-based hosts ripe for exploitation, as well as a mailserver with a web portal.

There were three web hosts. The site on 10.0.10.11 was vulnerabile to both SQLi and LFI. The SQLi provided a dumping of a employee records containing several hashed passwords which cracked for users within the network.

<img src = "/assets/images/redteamctfdc28/slqi.png">

<img src = "/assets/images/redteamctfdc28/database.png">

10.0.10.12 hosted a Wordpress blog. Once creds were obtained, it was possible to get a shell and flags from that box as well.

10.0.10.13 hosted the application that used leaked source code, and while the site says it was made by Milton, that was a bit of misdirection. This was one of the sticking points as we missed Michael's repo during recon and had to backtrack a bit.

<img src = "/assets/images/redteamctfdc28/milton.png">

The vulnerability identifed in the leaked source code was leveraged to gain a shell on the system through code injection. 

Mailboxes always present a wealth of information when accessed, and using each of the credentials obtained via exploitation efforts to raid user's inboxes yielded a lot of additional flags by checking out Docker images, inspecting attached documents, and other key information.

<img src = "/assets/images/redteamctfdc28/emailsample.png">

```
Milton,

I've reset your password to your home address <streetname>street<zipcode>.  
Please try to remember it in the future.

V/r,

-Postmaster
```
## Come on in, we are open! 

The 10.0.20.0/24 subnet contained a host with a share that could be accessed without authentication.

<img src = "/assets/images/redteamctfdc28/openshare.png">

<img src = "/assets/images/redteamctfdc28/secretzip.png">

Exploring this share revealed a password-protected zip file, which when cracked yielded the password for the michael.bolton user.

## Workstation rampage

The 10.0.30.0/24 subnet hosted 5 different Windows workstations (WS01-WS05). Using the previously attained credentials, hosts were then compromised and implanted with C2 beacons, and proxy pivots were established to go deeper into the network. Pivoting through these hosts allowed us to reach the 10.0.60.0/24 network.  

<img src = "/assets/images/redteamctfdc28/grunts.png">

Looking at Active Directory data revealed that michael.bolton also had an admin-type account, michael.bolton.adm. Michael was guilty of password reuse for an administrator account, and this allowed us to log into the host at .203 as an administrator.

Exploring this host revealed saved data for PuTTY which showed michael.bolton SSHing into the host at 10.0.60.45 as the user "michael". Attempting to SSH into this host with the credentials on hand failed, which led to further digging on Michael's workstation. Inspecting the registry gave us the password needed to access this host. 

<img src = "/assets/images/redteamctfdc28/putty_registry.png">

## Devnet Freeloading

After plundering the Windows workstations for all the flags, credentials, and clues possible, the next stop was the 10.0.60.0/24 subnet which housed two Linux boxes used for development: HERMAN and NAIDU, which are the last names of the actors that play Michael and Samir, respectively.

Once again these hosts contained several flags. Of note was some fun with 1Password on Samir's dev box. Through a combination of in-memory creds and accessing his Firefox browser's 1Password plugin via a portforwarded VNC session, it was possible to retrieve his secret key and an additional password to completely access his 1Password secrets.

<img src = "/assets/images/redteamctfdc28/1password.png">

Also of major note was the discovery of the 10.0.70.0/24 subnet, including credentials to SSH into the host at 10.0.70.10. 

<img src = "/assets/images/redteamctfdc28/helk.png">

## What the HELK?

The 10.0.70.0/24 subnet could be pivoted to from the dev hosts on the 10.0.60.0/24 network by either SSHing directly from either HERMAN or NAIDU, or by using something like sshuttle. The only host that was accessed was the host at .10, which was running an ELK stack. 

In addition to a bunch of flags, an incident response report could be found on the filesystem which outlined a network breach. 

<img src = "/assets/images/redteamctfdc28/IR.png">

This gave a link to an external S3 bucket which contained a sample of the malware used during the breach. 

<img src = "/assets/images/redteamctfdc28/incident.png">

Downloading this file, it was determined to be a .NET executable, and loading this into dnSpy allowed us to find out how it functions in addition to a password. The executable was nothing more than a bindshell running on port 2020 which prompts for the "HackedTheGibson!" password when connecting to it. 

<img src = "/assets/images/redteamctfdc28/bindshell.png">

## Yeaaah, you've been pwned. 

The 10.0.40.0/24 subnet was accessible through the 10.0.70.0/24 network, and personally I just used a separate sshuttle to communicate directly from my local host. Lucky for us, Initech did not have any of the mitigations from the report in place, which meant that the malware was still active on the infected host. Connecting to the bind shell on port 2020, the recovered password was used and it was possible to access CEO2 as dom.portwood. 

`AlwaysInstallElevated` was present for this user, which means that a malicious .msi file can be created and then ran as SYSTEM.

```
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}"><Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="AlwaysInstallElevated" status="AlwaysInstallElevated" image="12" changed="2020-08-06 01:33:03" uid="{99501837-5199-4107-907B-795024EF25EF}" bypassErrors="1"><Properties action="U" displayDecimal="0" default="0" hive="HKEY_CURRENT_USER" key="SOFTWARE\Policies\Microsoft\Windows\Installer" name="AlwaysInstallElevated" type="REG_DWORD" value="00000001"/></Registry>
```
A simple payload was made to add a local admin to the machine, and once on the machine in an elevated context, passwords were extracted from memory revealing the bill.lumbergh password affording us access to CEO1.

If you've seen Office Space, then surely you have been wondering when the printer destruction would come about in this scenario, and rest assured the organizers made sure to add this fun detail. Once on Bill Lumbergh's host, a program was found that communicates with a printer over port 9100.

<img src = "/assets/images/redteamctfdc28/tpsprinter.png">

This encompassed two pwn-type challenges with ARM architecture worth a ton of points, and our teammate Faith went absolutely HAM sandwich on these challenges.

# Final Results and Thoughts

Neutrino Cannon placed 1st in the qualifiers and 2nd in the finals. 

<img src = "/assets/images/redteamctfdc28/quals_scoreboard.png">
<img src = "/assets/images/redteamctfdc28/finalscoreboard.png">

We definitely hit some walls which caused a bottleneck, but we managed to make a pretty significant comeback after breaking down the barriers that were holding us back (not to mention overcoming mental fatigue). Everyone on the team contributed to make this possible, and even though we weren't able to lock in first place, the teamwork was phenominal and we all gave it our best.  

## Lessons learned and considerations for participating in future CTFs like this

Heading into the CTF, the plan was to have a dedicated host for a communal C2 server, take time and log all bits of data, and stay super structured. A couple of hours into the competition I was reminded of a wise Snart talking to Flash about plans...

<iframe width="560" height="315" src="https://www.youtube.com/embed/00RIkdLPqAs" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

The structure started to collapse a bit after a certain point with several C2 servers being stood up, and it became harder to track all data for several reasons (lack of communication, etc.), so a couple takeaways for next time would definitely be:

- Too many cooks in the kitchen is a real thing. Splitting the team into dedicated groups based on specialities or tasks is likely the way to go. While this is often the case for a real red team operation, when you only have 24 hrs and it's a time-attack type of deal, it makes it difficult because there is the notion to go as fast as possible. A good balance of this would be optimal.

- Better data logging is key. Just like real operations again, passing off discovered data to teammates so that they can take the torch and run with it, without having to ask too many questions, is important. This also allows for a good transition between players so people can rest their minds for a bit. We used Trello for all discovered data, but there were times data was not added or lost in the mix of Discord chat.

- Better communication and coordination is the most important factor in my opinion. Things became quite hectic with different C2s, different beacons, and stepping on toes via RDP connections, etc. It would likely be best to have some kind of chart showing who is on what host at any given time. Keeping clean voice comms will also go a long way--mainly cutting down on banter and random chatting to ensure transmission of key communications.

## Conclusion

It was a frenetic 72 hours, but it was such a good CTF! Everyone from the Red Team Village deserves major props for delivering an incredible experience to so many participants. The challenges were appropriate for the time frame and well thought out, and the theme was too good! Neutrino Cannon will be looking forward to more CTFs from the Red Team Village in the future, and can't wait to see what the organizers come up with next time.