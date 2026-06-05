# Scenario & Objective

The accountant at the company received an email titled "Urgent New Order" from a client late in the afternoon. When he attempted to access the attached invoice, he discovered it contained false order information. Subsequently, the SIEM solution generated an alert regarding downloading a potentially malicious file. Upon initial investigation, it was found that the PPT file might be responsible for this download. Could you please conduct a detailed examination of this file?

- **Category**: Threat Intel
- **Tools**: VirusTotal, ANY.RUN

## Overview

The malicious PPT file, created on `2022-09-28 17:40:46 UTC`, executed the malware upon opening. Post-infection, the malware first requested the `sqlite3.dll` library - used to read browser credential databases - and communicated with its C2 server at `http://171.22.28.221/5c06c05b7b34e8e6.php`. It used **RC4 encryption** (key: `5329514621441247975720749009`) to decrypt its base64-encoded strings and employed credential-stealing techniques categorized under `MITRE ATT&CK T1555` (Credentials from Password Stores).

After successfully exfiltrating the user's data, the malware performed anti-forensic cleanup by deleting all DLL files from `C:\ProgramData` and then self-deleted after a **5s** delay.

# Answer the Questions

**Q1: Determining the creation time of the malware can provide insights into its origin. What was the time of malware creation?**

From Detail tab, History category, I found the creation time of the malware is `2022-09-28 17:40:46 UTC`.
<p align="center">
  <img src="Image 1 - Malware creation time.webp" alt="Malware creation time" /> <br />
  <em>Image 1: Malware creation time</em>
</p>

**Q2: Identifying the command and control (C2) server that the malware communicates with can help trace back to the attacker. Which C2 server does the malware in the PPT file communicate with?**

I found the information of C2 server that malware connect with in Relation tab, Contacted URLs category. 
<p align="center">
  <img src="Image 2 - URL of C2 server that malware connect with.webp" alt="URL of C2 server that malware connect with" /> <br />
  <em>Image 2: URL of C2 server that malware connect with</em>
</p>

In general, the `.dll` library acts as a local Windows loader (often via hijacking) to establish persistence and evade detection. Attacker often place the malicious `dll` file in an application's path. When the application runs, it loads the malicious `.dll` file instead of the legitimate one (or run both file), allowing the malware to run with the same privileges as the application. 

Meanwhile, The PHP component is typically placed on a web server to act as a backdoor or exfiltrate data. So in this case, my answer is the url [http://171.22.28.221/5c06c05b7b34e8e6.php](https://www.virustotal.com/gui/url/205d797a462e377eb12371364bcb6ee85628f82a99509467c35b9866cf45c36b).

**Q3: Identifying the initial actions of the malware post-infection can provide insights into its primary objectives. What is the first library that the malware requests post-infection?**

As I said above, the `sqlite3.dll` is the library that the malware request. In the image 2, there is only 2 URLs that the malware contacted with, so maybe `sqlite3.dll` is the correct answer. 

But to verify that information, I go to File Dropped category from Behavior tab. This category refers to files that are created and written to a disk during the automated sandbox execution of the malware.
<p align="center">
  <img src="Image 3 - File Dropped.webp" alt="File Dropped" /> <br />
  <em>Image 3: File Dropped</em>
</p>

So my answer is `sqlite3.dll`.

**Q4: By examining the provided [Any.run report](https://any.run/report/a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb/d55e2294-5377-4a45-b393-f5a8b20f7d44), what RC4 key is used by the malware to decrypt its base64-encoded string?**

From the Malware configuration category, I found the RC4 key is `5329514621441247975720749009`
<p align="center">
  <img src="Image 4 - RC4 key.webp" alt="RC4 key" /> <br />
  <em>Image 4: RC4 key</em>
</p>

**Q5: By examining the MITRE ATT&CK techniques displayed in the [Any.run sandbox report](https://app.any.run/tasks/d55e2294-5377-4a45-b393-f5a8b20f7d44), identify the main MITRE technique (not sub-techniques) the malware uses to steal the user’s password.**

From the VPN.exe process, I found that there are 2 MITE ATT&CK that steal user credentials. And both have same main MITRE ATT&CS `T1555`.
<p align="center">
  <img src="Image 5 - MITRE ATT&CK.webp" alt="MITRE ATT&CK" /> <br />
  <em>Image 5: MITRE ATT&CK</em>
</p>

**Q6: By examining the child processes displayed in the [Any.run sandbox report](https://app.any.run/tasks/d55e2294-5377-4a45-b393-f5a8b20f7d44), which directory does the malware target for the deletion of all DLL files?**

I found the information in the cmd.exe process `del "C:\ProgramData\*.dll`. This command will delete all DLL files (`*.dll`) in the `C:\ProgramData` folder.
<p align="center">
  <img src="Image 6 - Directory that delete all DLL files.webp" alt="Directory that delete all DLL files" /> <br />
  <em>Image 6: Directory that delete all DLL files</em>
</p>

**Q7: Understanding the malware's behavior post-data exfiltration can give insights into its evasion techniques. By analyzing the child processes, after successfully exfiltrating the user's data, how many seconds does it take for the malware to self-delete?**

From the timeout.exe process, I found the command `timeout /t 5`. This command will pause the process after `5s`.
<p align="center">
  <img src="Image 7 - Timeout.webp" alt="Timeout" /> <br />
  <em>Image 7: Timeout</em>
</p>