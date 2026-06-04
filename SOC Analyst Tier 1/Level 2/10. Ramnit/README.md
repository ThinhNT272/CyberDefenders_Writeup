# Scenario & Objective

Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. My task is to analyze this dump, trace the malware’s actions, and report key findings

- **Category**: Endpoint Forensics
- **Tools**: Volatility 3, VirusTotal, IP Location
## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)
# Analysis

First, I check with plugin `windows.pslist`. But it seems nothing suspicious. So I check for command line information. Almost the processes run through "system32" folder, quite legitimate. There is only 2 process `OneDrive.exe` (PID 7780) and `ChromeSetup.exe` (PID 4628) run under user `Alex` permission.
<p align="center">
  <img src="./Assets/Image 1 - Suspicious processes.webp" alt="Suspicious processes" /> <br />
  <em>Image 1: Suspicious processes</em>
</p>

I want to verify these files, so I use plugin `windows.dumpfiles` to know full name of these files. So, the full name file. And from that, I can have its SHA256 hash value 
<p align="center">
  <img src="./Assets/Image 2.1 - Full name file of ChromeSetup.exe.webp" alt="Full name file of ChromeSetup.exe" /> <br />
  <img src="./Assets/Image 2.2 - Full name file of OneDrive.exe.webp" alt="Full name file of OneDrive.exe" /> <br />
  <em>Image 2: Full namefile of processes</em>
</p>
<p align="center">
  <img src="./Assets/Image 3 - SHA256 hash value of 2 files.webp" alt="SHA256 hash value of 2 files" /> <br />
  <em>Image 3: SHA256 hash value of 2 files</em>
</p>

- ChromeSetup.exe:
	- Filename: `file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img`
	- SHA256 hash value: `1ac890f5fa78c857de42a112983357b0892537b73223d7ec1e1f43f8fc6b7496`
- OneDrive.exe:
	- Filename: `file.0xca82b7c72ce0.0xca82b7ecbda0.ImageSectionObject.OneDrive.exe.img`
	- SHA256 hash value: `ae1800f077e588d2e123f00f5a0518e2f8a2e58defaee9e81a2c7a89332d71dc`

Then I check these hash in VirusTotal to verify malicious files.
<p align="center">
  <img src="./Assets/Image 4.1 - Verify malicious ChromeSetup.exe.webp" alt="Verify malicious ChromeSetup.exe" /> <br />
  <img src="./Assets/Image 4.2 - Verify malicious OneDrive.exe.webp" alt="Verify malicious OneDrive.exe" /> <br />
  <em>Image 4: Verify malicious files</em>
</p>

So I know the file `ChromeSetup.exe` is  a malicious file and `OneDrive.exe` may be a malicious.

Then I want to know more information about these 2 files, so I check for plugin `windows.pstree` to know whether these files generate another malicious processes or not. But it seems nothing special.

Then I check for `windows.netscan` to find whether malicious process connect to C2 server or not.
<p align="center">
  <img src="./Assets/Image 5.1 - Malicious connect to C2 Server.webp" alt="Malicious connect to C2 Server" /> <br />
  <img src="./Assets/Image 5.2 - Malicious IP information.webp" alt=" Malicious IP information" /> <br />
  <em>Image 5: Malicious connect to C2 Server</em>
</p>

So, the `ChromeSetup.exe` connect to IP `58.64.204.181` that come from `Hong Kong`. And `OneDrive.exe` donot connect out of Internet. 
# Answer the Questions

**Q1: What is the name of the process responsible for the suspicious activity?**

It is `ChromeSetup.exe`.

**Q2: What is the exact path of the executable for the malicious process?**

From the image 1, the executable path is `C:\Users\alex\Downloads\ChromeSetup.exe`.

**Q3: Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?**

It is `58.64.204.181`.

**Q4: To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?**

It is `Hong Kong`.

**Q5: Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?**

From VirusTotal, SHA1 hash value of `ChromeSetup.exe` is `280c9d36039f9432433893dee6126d72b9112ad2`.

**Q6: Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?**

From VirusTotal, the compilation timestamp for the malware is `2019-12-01 08:36:04 UTC`.
<p align="center">
  <img src="./Assets/Image 6 - Compilation timestamp of malware.webp" alt="Compilation timestamp of malware" /> <br />
  <em>Image 6: Compilation timestamp of malware</em>
</p>

**Q7: Identifying the domains associated with this malware is crucial for blocking future malicious communications and detecting any ongoing interactions with those domains within our network. Can you provide the domain connected to the malware?**

From VirusTotal, the malicious file connect to 4 domains.
<p align="center">
  <img src="./Assets/Image 7 - Malicious file connect to domain.webp" alt="Malicious file connect to domain" /> <br />
  <em>Image 7: Malicious file connect to domain</em>
</p>

But only domain `dnsnb8.net` matches with answer format.

