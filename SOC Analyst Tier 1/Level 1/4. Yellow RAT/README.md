# Scenario & Objective

During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation. Your task is to investigate this incident and gather as much information as possible.

- **Category**: Threat Intel
- **Tools**: VirusTotal, Red Canary

Before do the lab, we need to know what is RAT? Basically, a Remote Access Trojan (RAT) is malicious software that gives attackers full administrative control over a victim’s computer or server without their consent.

## Overview

The malware `Yellow Cockatoo RAT`, compiled on `2020-09-24 18:26:47 UTC` and first submitted to VirusTotal on `2020-10-15 02:47:37 UTC`, operated as a DLL file with the common filename `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`. Upon infection, it dropped a persistence file named `solarmarker.dat` in the AppData folder and established communication with its C2 server at `https://gogohid.com`.

# Answer the Questions

**Q1: Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?**

From the Graph Summary category, go to see full graph and I found this.
<p align="center">
  <img src="Image 1 - RAT collection from graph view.webp" alt="RAT collection from graph view" /> <br />
  <em>Image 1: RAT collection from graph view</em>
</p>

Then I look at the name of the lab `Yellow RAT Lab`, so maybe `Yellow Cockatoo RAT` is correct answer. But I need to verify that by click the Source Link. From the page, there list the IoCs and I found the hash of malware in that list. So, the malware is `Yellow Cockatoo RAT.
<p align="center">
  <img src="Image 2 - IoCs of malware.webp" alt="IoCs of malware view" /> <br />
  <em>Image 2: IoCs of malware</em>
</p>

**Q2: As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?**

I found these files name in Detail tab, Names category. There are several files but only 1 match the format. This is `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`.
<p align="center">
  <img src="Image 3 - File name.webp" alt="File name" /> <br />
  <em>Image 3: File name</em>
</p>

**Q3: Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?**

Compilation timestamp is also called as creation timestamp because it is a value embedded by the compiler into the executable at the exact moment the code is built.

So, the compilation timestamp of the malware that infected out network is `2020-09-24 18:26:47 UTC`.
<p align="center">
  <img src="Image 4 - Compilation timestamp.webp" alt="Compilation timestamp" /> <br />
  <em>Image 4: Compilation timestamp</em>
</p>

**Q4: Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?**

From the image 4 above, I found that the first submitted of the malware to VirusTotal is `2020-10-15 02:47:37 UTC`.

**Q5: To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the .dat file that the malware dropped in the AppData folder?**

I check File system actions category and it has Files Dropped. But it seems not match the requirement. 
<p align="center">
  <img src="Image 5 - File system actions.webp" alt="File system actions" /> <br />
  <em>Image 5: File system actions</em>
</p>

So, I decide to search from the Internet and found this report of [Red Canary](https://redcanary.com/blog/threat-intelligence/yellow-cockatoo/) that mention exactly what I need.
<p align="center">
  <img src="Image 6 - Red Canary report.webp" alt="Red Canary report" /> <br />
  <em>Image 6: Red Canary report</em>
</p>

So, my answer is `solarmarker.dat`

**Q6: It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?**

From the image 6 above, I also know the C2 server of the malware is `https://gogohid.com`.