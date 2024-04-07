---
title: HTB Sherlocks Meerkat
layout: post
post-image: "/posts_media/meerkat/meerkat.jpg"
description: A detailed writeup on Meerkat, a Blue Team investigation by HackTheBox.
tags:
- hackthebox
- sherlocks
- writeup
- CTF
---

Let's start by reading the **scenario**:

>As a fast growing startup, Forela have been utilising a business management platform. Unfortunately our documentation is scarce and our administrators aren't the most security aware. As our new security provider we'd like you to take a look at some PCAP and log data we have exported to confirm if we have (or have not) been compromised.


The investigation has provided us with a file named `meerkat.zip`. This file contains a pcap and a JavaScript file that triggers alerts.

![Question 1 Meerkat](/posts_media/meerkat/meerkat_q1.PNG)

To answer the first question, let's open the pcap file. If we use a simple filter such as `http.request.method == "POST"` we can see several requests using the **POST** method to 172.31.6.44 that have `/bonita/loginservice` as the endpoint.
 
![Pcap screenshot Bonita](/posts_media/meerkat/pcap1.png)

Now I'm going to search for "Bonita" in the JS file.

![](/posts_media/meerkat/alert1.PNG)

And we can see that the answer to the first question is `BonitaSoft`

![](/posts_media/meerkat/meerkat_q2.PNG)

To answer the second question, let's follow the **TCP** flow of one of the packages that have `/bonita/loginservice` as an endpoint.

![](/posts_media/meerkat/pcap2.PNG)

From streams 1066 and 1067, we can see how first the attacker attempts to log in with `Adora.Mersh@forela.co.uk` and then with `Guss.Botten@forela.co.uk`

This suggests that the attacker is using a technique called [Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/).

![](/posts_media/meerkat/meerkat_q3.PNG)

Just filter for "CVE" on the JS file and look at `CVE-2022-25237`

![](/posts_media/meerkat/cve.png)

![](/posts_media/meerkat/meerkat_q4.png)

If we consult the documentation of [CVE-2022-25237](https://rhinosecuritylabs.com/application-security/cve-2022-25237-bonitasoft-authorization-bypass/) we can see that this vulnerability is a simple URL manipulation whereby adding `i18ntranslation` to the end of a URL users with no privileges can access privileged API endpoints. In a real-world scenario, this can lead to an RCE ([Remote Code Execution](https://owasp.org/www-community/attacks/Code_Injection))

![](/posts_media/meerkat/meerkat_q5.PNG)

In these situations, it is important to be extremely accurate, which is why I used <a href="https://tshark.dev/" style="color: blue; font-weight: bold;">tshark</a> to avoid guessing.

```bash
 tshark -r meerkat.pcap -Y 'http.request.method == "POST" && http.request.uri == "/bonita/loginservice"' -e http.file_data -T fields > file.txt 
```
<br>
Now I have to decode the output and count the number of unique users

```python
from urllib.parse import unquote_plus
import re

path = 'file.txt'

def count(path):
    with open(path, 'r') as file:
        data = file.read()
    usernames = re.findall(r'username=([^&\n]+)', data)
    unique = {unquote_plus(username) for username in usernames if 'install' not in unquote_plus(username)}

    print(f"{len(unique)}")
    return unique

unique = count(path)
```
<br>
The output of this script is `56`, which is the number of unique username:password combinations used.

![](/posts_media/meerkat/meerkat_q6.PNG)

Just filter for `http.response.code == 204` on Wireshark and follow the HTTP stream. In this case, we filter for [HTTP response code 204](https://www.akto.io/academy/204-status-code), which indicates a **successful** request.

![](/posts_media/meerkat/wireshark_q6.png)

| Email      | Password |
| ----------- | ----------- |
| seb.broom@forela.co.uk      | g0vernm3nt       |

![](/posts_media/meerkat/meerkat_q7.PNG)

If we follow TCP stream number 1147, we can see that the attacker ran **wget** to download the content from `https://pastes.io/raw/bx5gcr0et8`. 

![](/posts_media/meerkat/wireshark_q7.PNG) 

So the answer is `pastes.io`

![](/posts_media/meerkat/meerkat_q8.PNG)

This question has been changed, but there are 2 methods to solve it:

**First one**:

```bash
wget https://pastes.io/raw/bx5gcr0et8
```
<br> 
```bash
md5sum bx5gcr0et8
```
<br> 

**Second one**:

On Wireshark go to `File` > `Export Objects` and filter for `bx5` in the search bar

![](/posts_media/meerkat/wireshark_q8.PNG)

Now save the file and run **md5sum** on it.

```bash
md5sum bx5gcr0et8
```
<br> 

![](/posts_media/meerkat/meerkat_q9.png)

We can get the answer from the destination of the public key.

![](/posts_media/meerkat/q9.PNG)

File to gain persistence: `/home/ubuntu/.ssh/authorized_keys`

Note that in a real-world scenario, an adversary can generate the SSH keys using `ssh-keygen`, which will generate the public key `id_rsa.pub`.

![](/posts_media/meerkat/meerkat_q10.PNG)

To get the answer I just googled `/home/ubuntu/.ssh/authorized_keys MITRE`. The Technique ID is `T1098.004`, which consists of modifying authorised_keys of the SSH to maintain persistence. 

If you want to learn more about this sub-technique go to [this page](https://attack.mitre.org/techniques/T1098/004/)

---
### Conclusion 

From this beautiful investigation, we learnt:

- What is CVE-2022-25237 (Bonitasoft Authorization Bypass)

- The use of Credential Stuffing    

- A sub-technique of persistence via SSH Authorized Keys (T1098.004)

---
