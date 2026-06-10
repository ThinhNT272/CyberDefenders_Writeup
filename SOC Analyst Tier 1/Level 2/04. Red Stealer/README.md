# Scenario & Objective

You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.

Your task is to investigate this executable by analyzing its hash. The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.

- **Category**: Threat Intel
- **Tools**: VirusTotal, MalwareBazaar, ThreatFox

## Overview

During a security investigation, a suspicious executable named **WexTract** was found on a colleague's computer. Analysis of the file indicates that it is a **RedLine Stealer** (also known as **RecordStealer**) Trojan, which was first observed on VirusTotal on **2023-10-06 at 04:41:50 UTC**.

The malware was designed to collect sensitive data from the local system (MITRE ATT&CK technique **T1005**) for exfiltration. To achieve this, it uses **ADVAPI32.dll** for privilege escalation. After execution, the malware performs DNS queries to resolve social media domains like **facebook.com** and communicates with a Command and Control (C2) server at IP address **77.91.124.55** on port **19071**.

# Answer the Questions

**Q1: Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?**

From VirusTotal, Microsoft categorised this malware as `Trojan:Win32/Redline!rfn`
<p align="center">
  <img src="./Assets/Image 1. Microsoft categorise malware.webp" alt="Microsoft categorise malware" /> <br />
  <em>Image 1: Microsoft categorise malware</em>
</p>

**Q2: Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?**

From the `Details` tab, `Names` category, I found other name of this malware `WexTract`.
<p align="center">
  <img src="./Assets/Image 2 - Other name of malware.webp" alt="Other name of malware" /> <br />
  <em>Image 2: Other name of malware</em>
</p>

**Q3: Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware's first submission to VirusTotal?**

From `Details` tab, `History` category, I know the UTC timestamp of malware's first submission is `2023-10-06 04:41:50 UTC`.
<p align="center">
  <img src="./Assets/Image 3 - Malware's first submission timestamps.webp" alt="Malware's first submission timestamps" /> <br />
  <em>Image 3: Malware's first submission timestamps</em>
</p>

**Q4: Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware's data collection from the system before exfiltration?**

To know the MITRE ATT&CK technique ID for the malware's data collection, I check `Behavior` tab and found `T1005 - Data From Local System` from `Collection` tactic.
<p align="center">
  <img src="./Assets/Image 4 - Mitre att&ck technique ID for malware's data collection.webp" alt="Mitre att&ck technique ID for malware's data collection" /> <br />
  <em>Image 4: Mitre att&ck technique ID for malware's data collection</em>
</p>

**Q5: Following execution, which social media-related domain names did the malware resolve via DNS queries?**

I search from `Contacted Domains` category to find every domain the malware resolve. And I found the social media-related domain is `facebook`.
<p align="center">
  <img src="./Assets/Image 5 - Domain names that the malware resolve via DNS query.webp" alt="Domain names that the malware resolve via DNS query" /> <br />
  <em>Image 5: Domain names that the malware resolve via DNS query</em>
</p>

**Q6: Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?**

I search for `IP Traffic` category, which represent IP traffic when executing the fiels being studied. There are many IP traffic was recorded based on different vendor. But the first one `77.91.124.55:19071` seems like more public because 3 vendors (C2AE, VMRAY, ZENBOX) recorded it.
<p align="center">
  <img src="./Assets/Image 6 - Recorded IP traffic.webp" alt="Recorded IP traffic" /> <br />
  <em>Image 6: Recorded IP traffic</em>
</p>

**Q7: YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "`Varp0s`" that detects the identified malware?**

Search in MalwareBazaar follow their search syntax `sha256:248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B`, there is only 1 result by reporter `abuse_ch`. And from the `YARA` category, the rule that created by "Varp0s" is `detect_Redline_Stealer`.
<p align="center">
  <img src="./Assets/Image 7 - YARA rule by Varp0s.webp" alt="YARA rule by Varp0s" /> <br />
  <em>Image 7: YARA rule by Varp0s</em>
</p>

**Q8: Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?**

Following the search syntax in ThreatFox, I search for malware name that I know in MalwareBazaar `malware:RedLine`. There are so many result but I go to 1 of 2 IOC below because it has the same reporter `abuse_ch` with MalwareBazaar above.
<p align="center">
  <img src="./Assets/Image 8 - result of malware in ThreatFox.webp" alt="result of malware in ThreatFox" /> <br />
  <em>Image 8: result of malware in ThreatFox</em>
</p>

Then I know the different malware alias associated with malicious IP address is `RECORDSTEALER`.
<p align="center">
  <img src="./Assets/Image 9 - Different malware alias.webp" alt="Different malware alias" /> <br />
  <em>Image 9: Different malware alias</em>
</p>

**Q9: By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?**

Back to Virustotal, from `Details` tab, `Imports` category, there are many DLLs, but the first one have `AdjustTokenPrivileges` and `LookupPrivilegeValueA` description. So, malware use the `ADVAPI32.dll` for privilege escalation. 
<p align="center">
  <img src="./Assets/Image 10 - DLLs for privilege escaltion.webp" alt="DLLs for privilege escaltion" /> <br />
  <em>Image 10: DLLs for privilege escaltion</em>
</p>