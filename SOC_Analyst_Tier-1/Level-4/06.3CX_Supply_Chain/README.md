# Scenario & Objective

3CX is a phone system for business that provides Unified Communications, including VoIP calling, video conferencing, live chat, and SMS. It allows businesses to host their own communications on-premise, in a private cloud, or via 3CX-hosted solutions, offering flexibility and avoiding high per-user, per-month costs

- **Category**: Threat Intel
- **Tools**: VirusTotal

After updating 3CX software, the IT team found the antivirus alerts flag sporadic instances of the software being wiped from some workstations while others remain unaffected. Employees report issues with the 3CX app, and the IT security team identifies unusual communication patterns linked to recent software updates. This is a supply chain attack.

As the threat intelligence analyst, I need to understand how the attackers compromised the 3CX app, identify the potential threat actor involved, and assess the overall extent of the incident.

## Overview

The advanced persistent threat (APT) group responsible for this incident is LABYRINTH CHOLLIMA, which is also widely known as Lazarus. They use supply chain attack method to compromise the 3CX DesktopApp Electron Windows application, specifically versions `18.12.407` and `18.12.416`. 

From about 2023-03-13 06:33:26 UTC, Lazarus create a `.msi` malware that contain two Trojan DLLs: `ffmpeg.dll` and `d3dcompiler_47.dll`. 

They aimed to infiltrate target networks to execute malicious code, establishing persistence via DLL side-loading (MITRE T1574) while using RC4 encryption and VMWare-targeted virtualization evasion to bypass defensive mechanisms.

# Answer the Questions

**Q1: Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX running on Windows have been flagged as malware?**

As I know this is a supply chain attack, I can research "3CX supply chain attack" from the Internet and know that this is CVE-2023-29059 from [Fortinet](https://www.fortinet.com/blog/threat-research/3cx-desktop-app-compromised). Then I search the CVE in [NVD - CVE-2023-29059](https://nvd.nist.gov/vuln/detail/cve-2023-29059) and find that:

<p align="center"><em>This affects versions 18.12.407 and 18.12.416 of the 3CX DesktopApp Electron Windows application shipped in Update 7</em></p>

So, there are 2 versions of 3CX running on Windows have been flagged as malware.

**Q2: Determining the age of the malware can help assess the extent of the compromise and track the evolution of malware families and variants. What's the UTC creation time of the `.msi` malware?**

From VirusTotal in Details tab and History category, I know the creation time of the malware is "2023-03-13 06:33:26 UTC"
<p align="center">
  <img src="./Assets/Image 1 - Malware Creation Time.webp" alt="Malware Creation Time" /><br>
  <em>Image 1: Malware Creation Time</em>
</p>

**Q3: Executable files (`.exe`) are frequently used as primary or secondary malware payloads, while dynamic link libraries (`.dll`) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (`.msi`) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the `.msi` file?**

To know which `.dll` files that the attacker uses in the malicious, check VirusTotal, Relations tab, Bundled Files category, which represent the child files in the malware. 
<p align="center">
  <img src="./Assets/Image 2 - '.dll' files.webp" alt="'.dll' files" /><br>
  <em>Image 2: ".dll" files</em>
</p>

So, the malicious has 2 `.dll` files `ffmpeg.dll` and `d3dcompiler_47.dll`.

**Q4: Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE Technique ID employed by the `.msi` files to load the malicious DLL?**

I check from Behavior tab, MITRE ATT&CK Tactics and Techniques category. 
<p align="center">
  <img src="./Assets/Image 3 - MITE ATT&CK Techniques.webp" alt="MITE ATT&CK Techniques" /><br>
  <em>Image 3: MITE ATT&CK Techniques</em>
</p>

So, `msi` file use T1574 technique to load the malicious DLL.

**Q5: Recognizing the malware type (`threat category`) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the threat category of the two malicious DLLs?**

Go back to the Bundled Files category from the Q3 step and click to 2 file `dll`, I find that the threat category of 2 malicious DLLs is Trojan.
<p align="center">
  <img src="./Assets/Image 4 - ffmpeg.dll file.webp" alt="ffmpeg.dll" /><br>
  <em>Image 4: ffmpeg.dll file</em>
</p>

<p align="center">
  <img src="./Assets/Image 5 - d3dcompiler_47.dll.webp" alt="d3dcompiler_47.dll" /><br>
  <em>Image 5: d3dcompiler_47.dll</em>
</p>

**Q6: As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?**

Check MITRE ATT&CK Tactics and Techniques category like Q4, I can see that the malicious DLLs use MITRE T for the virtualization/sandbox evasion techinque.
<p align="center">
  <img src="./Assets/Image 6 - virtualization or sandbox evasion techinque.webp" alt="Virtualization/sandbox evasion techinque.dll" /><br>
  <em>Image 6: Virtualization/sandbox evasion techinque</em>
</p>

**Q7: When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?**

Check Capabilities category from Behavior tab of `ffmpeg.dll` file, I can see that the hypervisor is targeted by the anti-analysis techniques in the `ffmpeg.dll` file is VMWare. 
<p align="center">
  <img src="./Assets/Image 7 - anti-analysis in the ffmpeg.dll file.webp" alt="Anti-analysis in the ffmpeg.dll file" /><br>
  <em>Image 7: Anti-analysis in the ffmpeg.dll file</em>
</p>

**Q8: Identifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What encryption algorithm is used by the `ffmpeg.dll` file?**

Still in Capabilities category, I know `ffmpeg.dll` use RC4 algorithm for encryption.
<p align="center">
  <img src="./Assets/Image 8 - encrypted algorithm of ffmpeg.dll file.webp" alt="Encrypted algorithm of ffmpeg.dll file" /><br>
  <em>Image 8: Encrypted algorithm of ffmpeg.dll file</em>
</p>

**Q9: As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?**

After researching, I know that LABYRINTH CHOLLIMA is the group that attack 3CX supply chain based on an article [CrowdStrike Falcon Platform Detects and Prevents Active Intrusion Campaign Targeting 3CXDesktopApp Customers](https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/). This group is well-known with another name, Lazarus.