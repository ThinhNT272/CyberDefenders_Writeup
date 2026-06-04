# Scenario & Objective

Unusual network activity has been detected within a university environment, indicating potential malicious intent. These anomalies, observed six hours ago, suggest the presence of command and control (C2) communications and other harmful behaviors within the network.

My team has been tasked with analyzing recent network traffic logs to investigate the scope and impact of these activities. The investigation aims to identify command and control servers and uncover malicious interactions.

- **Category**: Threat Hunting
- **Tools**: Splunk, VirusTotal
## Overview

On **10/08/2011**, starting at **09:01:40**, unusual network activity was detected on a targeted host (**147.32.84.165**) within a university network. 

The investigation using Splunk and VirusTotal showed that the host was compromised after downloading a malicious executable named **3425.exe** from **nocomcom.com** (IP **195.88.191.59**). Following this initial compromise, the malware used a custom User-Agent (`Download`) to fetch five additional malicious files (including **client.exe**, **chooseee.exe**, and a malicious file disguised as **kx4.txt**). These connections were established with command and control (C2) servers to download second-stage payloads and expand the threat actor's control.
# Analysis

At first, I follow sourcetype `suricata` because it stands out of other `zeek` logs. Then I check event_type field.
<p align="center">
  <img src="./Assets/Image 1.1 - Suricata sourcetype.webp" alt="Suricata sourcetype" /> <br />
  <img src="./Assets/Image 1.2 - event_type in suricata log.webp" alt="event_type in suricata log" /> <br />
  <em>Image 1: Network log</em>
</p>

I have a hint from the scenario as malicious connect with C2 out of the network. So someone must download it malicious file. That why I check for `http` protocol, especially `GET` method. From there, I found the `http.http_user_agent=Download` - which is an HTTP request header sent by suspicious software (like a download manager, web scraper, or script), not a browser or any legitimate application because of the format failure.

There are only 7 events from `9:01:40` to `11:02:12` in `10/08/2011`. I want to know more about which file that the host download, what is the file name, what is domain name of the malicious website, so I filter with the SPL and got this. 

```SPL
index=* sourcetype=suricata event_type=http http.http_method=GET http.http_user_agent=Download
| stats values(src_ip) as src_ip values(src_port) as src_port values(dest_port) as dest_port values(http.hostname) as hostname values(http.url) as url by dest_ip
```

<p align="center">
  <img src="./Assets/Image 2 - Suspicious files were downloaded.webp" alt="Suspicious files were downloaded" /> <br />
  <em>Image 2: Suspicious files were downloaded</em>
</p>

There are some suspicious `file.exe` with 3 domain name here. And all 3 domain names are marked as malicious in VirusTotal.
<p align="center">
  <img src="./Assets/Image 3.1 - Malicious Domain 1.webp" alt="Malicious Domain 1" /> <br />
  <img src="./Assets/Image 3.2 - Malicious Domain 2.webp" alt="Malicious Domain 2" /> <br />
  <img src="./Assets/Image 3.3 - Malicious Domain 3.webp" alt="Malicious Domain 3" /> <br />
  <em>Image 1: Network log</em>
</p>

But as I said above, these packets requested with `http.http_user_agent=Download`, which means there is already have a suspicious file in the server before this time (before `9:01:40` in `10/08/2011`). I want to know the first malicious `file.exe` that compromised the server, so I filter with this SPL.

```SPL
index=* sourcetype=suricata event_type=http AND http.url="*.exe*"
| eval time = date_hour . ":" . date_minute . ":" . date_second 
| stats values(dest_ip) as dest_ip values(src_ip) as src_ip values(src_port) as src_port values(dest_port) as dest_port values(http.http_user_agent) as user_agent values(http.hostname) as hostname values(http.url) as url by time
```

<p align="center">
  <img src="./Assets/Image 4 - The first malicious file.webp" alt="The first malicious file" /> <br />
  <em>Image 4: The first malicious file</em>
</p>

As the image above, I know the first malicious file that compromised server through browser is `/temp/3425.exe?t=0.3419458` from `nocomcom.com` with IPv4 `195.88.191.59` at `9:1:40` in `10/08/2011`.

Then `3425.exe` download other file:

- `ff.exe` from `94.63.149.152`.
- `kp.exe` from `60.190.223.75`.
- `client.exe`, `fjuivgfhurew.exe` and `chooseee.exe` from `195.88.191.59`.

Then I want to know what did these files do in the server but I cannot find any thing special.
# Answer the Questions

**Q1: During the investigation of network traffic, unusual patterns of activity were observed in Suricata logs, suggesting potential unauthorized access. One external IP address initiated access attempts and was later seen downloading a suspicious executable file. This activity strongly indicates the origin of the attack. What is the IP address from which the initial unauthorized access originated?**

It is `195.88.191.59`.

**Q2: Investigating the attacker’s domain helps identify the infrastructure used for the attack, assess its connections to other threats, and take measures to mitigate future attacks. What is the domain name of the attacker server?**

It is `nocomcom.com`.

**Q3: Knowing the IP address of the targeted system helps focus remediation efforts and assess the extent of the compromise. What is the IP address of the system that was targeted in this breach?**

It is `147.32.84.165`.

**Q4: Identify all the unique files downloaded to the compromised host. How many of these files could potentially be malicious?**

As I said above, there are totally 6 suspicious files `3425.exe`, `ff.exe`, `kp.exe`, `client.exe`, `fjuivgfhurew.exe` and `chooseee.exe`. But to know these files unique or not, I need to check theri hash through `sourcetype="zeek:files"` with 3 malicious IP addresses.

```SPL
index=* sourcetype="zeek:files" AND tx_hosts IN ("195.88.191.59", "60.190.223.75", "94.63.149.152")
```

<p align="center">
  <img src="./Assets/Image 5 - MD5 hash of suspicious files.webp" alt="MD5 hash of suspicious files" /> <br />
  <em>Image 5: MD5 hash of suspicious files</em>
</p>

There are 6 values hash correspondence  6 suspicious files. I check these hash in VirusTotal and know `5` out of 6 is malicious files.

| MD5 Hash                                                           | File Name          | VirusTotal Flag |
| ------------------------------------------------------------------ | ------------------ | --------------- |
| `9c1623f0d38e28e9594f2ef31a7ec909291c4fdb05a777dccd2e936a7f406011` |                    | Safe            |
| `6fbc4d506f4d4e0a64ca09fd826408d3103c1a258c370553583a07a4cb9a6530` | `kx4.txt`          | Malicious       |
| `00f15e22ab95632fc51d09f179eb22f5a36e92f6e99390f08a4161f2f93e1717` | `fjuivgfhurew.exe` | Malicious       |
| `617520dbb4c29f0d072ffb6f9f637c558dc224441d235943957aaa8f5de8db6f` | `chooseee.exe`     | Malicious       |
| `6d8353efda8438bf2dff79d6a4c174d5593450858c74c45c6f2718927546c1bd` | `client.exe`       | Malicious       |
| `2ed4a4ad94c6148b013aecacae783748d51d429de4f1d477a79bbf025d03d47a` | `3425.exe`         | Malicious       |


**Q5: What is the SHA256 hash of the malicious file disguised as a `.txt` file?**

From VirusTotal, I have SHA256 value of `kx4.txt` file is `6fbc4d506f4d4e0a64ca09fd826408d3103c1a258c370553583a07a4cb9a6530`.