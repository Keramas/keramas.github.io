---
layout: post
title: 'More Active Directory Enumeration via MSSQL'
date: '2020-03-28T12:00:00.000-00:00'
author: Keramas
tags: [active directory, ldap, mssql, penetration testing]
---

In my [previous blog post](https://keramas.github.io/2020/03/22/mssql-ad-enumeration.html), RID bruteforcing was used to uncover a full list of Active Directory users via MSSQL injection. However, if the right circumstances are present, this can be a lot easier with valid AD creds and access to the MSSQL port--all thanks to the ability to perform LDAP queries from within MSSQL with `OpenQuery`. 

Here is a possible scenario: An externally-facing application server that also has the MSSQL port exposed is vulnerable to a SQL injection. The db user has extremely limited privileges, but we are able to get an NTLMv2 hash via `xp_dirtree` which ends up cracking.
Now we have valid Active Directory credentials, but the only avenue to use them is via MSSQL. It is not possible to hit LDAP or the DC directly due to firewalls, and the DB user does not have a mailbox.

Connecting to the MSSQL server with tools like `dbeaver` or `mssql-cli`, we don't find much in terms of juicy information right away. However, using SQL we can establish an `Active Directory Service Interface` (ADSI) linked server with the Active Directory credentials that we obtained, which will then allow us to perform LDAP queries with `OpenQuery`.

To accomplish this, we first establish the linked server:

```sql
EXEC master.dbo.sp_addlinkedserver @server = N'DEMO', 
@srvproduct=N'Active Directory Service Interfaces', 
@provider=N'ADSDSOObject', @datasrc=N'adsdatasource'
```

The `@server` value can be arbitrary, but it's something we will be using in subsequent queries. Next, we provide the credentials to use when connecting to the linked server.

```sql
EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname=N'DEMO',
@useself=N'False',@locallogin=NULL,
@rmtuser=N'<DOMAIN>\<Username>',@rmtpassword='<PASSWORD>'
```

If the account running the SQL server is in fact a domain account, we will still need to authenticate for LDAP queries; however, we do not need plaintext credentials to do this. We can just have the SQL server use the credentials of the account already running the database by using the `@useself = N'True'` arg.

```sql
EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname = N'DEMO', 
@locallogin = NULL , @useself = N'True'
```

Now that we are authenticated and our ADSI is set up, we have the ability to execute whatever LDAP queries our heart desires via the `OpenQuery` function. We can quickly extract a full list of Active Directory users, their email addresses, and other key information.

Items useful for future attacks:
- usernames
- email address
- user account properties 

```sql
(SELECT * FROM OPENQUERY(DEMO, 'SELECT sAMAccountName, mail, note, 
userAccountControl FROM ''LDAP://neutrino.local/DC=neutrino,DC=local'' 
WHERE objectCategory = ''Person'' AND objectClass = ''user'''))
```

<img src="/assets/images/ldap_mssql_dump.png" border="1">

While not too useful right now since in this scenario we have no way of authenticating to pivot into the network, we can still look over the `userAccountControl` values for account properties. The output is a decimal value indicating property flags active on the account. 

- `512` indicates a normal account
- A value of `4194304` indicates the `DONT_REQ_PREAUTH` flag, which means the account is ASREP-roastable.

Looking at the `ccheese` user, `512 + 4194304 = 4194816`, meaning a normal account that doesn't require preauth. If we managed to get onto the VPN or get past the perimeter, we could then use this information. 

After we are finished, we will tear down the linked server and drop the login session to clean up.
```sql
EXEC master.dbo.sp_dropserver @server=N'DEMO', @droplogins='droplogins'
```

Once again, while this is not a new technique or novel knowledge, using native aspects of MSSQL in an offensive manner when your environment is stacked against you, will make the difference between being able to perform follow-up attacks and calling it a day. Now that we have a full, valid list of emails and AD usernames, we can password spray O365 or VPNs to see if any users have weak credentials to allow us to break through the perimeter. 

