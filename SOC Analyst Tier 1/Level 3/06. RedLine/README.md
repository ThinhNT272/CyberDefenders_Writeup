# Scenario & Objective

As a member of the Security Blue team, your assignment is to analyze a memory dump using Redline and Volatility tools. Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System (NIDS). Your investigation will identify the specific malware family employed in the attack and its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

- **Category**: Endpoint Forensics
- **Tools**: Volatility 3, Browser

## Overview

On **May 21, 2023**, a host compromise occurred on a workstation belonging to user **Tammam**. The incident unfolded through the following sequence of events:

* **NIDS Bypass (23:00:00 UTC):** The attacker bypassed the Network Intrusion Detection System (NIDS) by establishing an encrypted VPN connection using **Outline VPN** (`outline.exe` / `tun2socks.exe`). This encrypted tunnel allowed the external IP **33.121.43.65** to tunnel traffic into the host undetected.
* **C2 Connection (23:01:22 UTC):** Once inside the network, network communications were established with the attacker's Command and Control (C2) server at IP **77.91.124.20**, where the attacker accessed the malicious URL `http://77.91.124.20/store/games/index.php`.
* **Malware Execution (23:03:00 UTC):** The main malware executable **oneetx.exe** (PID `5480`), located in the temporary directory `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe`, was executed as a persistent process spawned by `svchost.exe`. A second instance of the malware (PID `5896`) spawned a child process **rundll32.exe** (PID `7732`). 

Memory forensics using Volatility revealed that the malware used `PAGE_EXECUTE_READWRITE` memory protections to perform code injection, a technique characteristic of the **RedLine Stealer** (Amedy) malware family. Traces of this attack remain on the host in the temporary application directory and active process memory maps.

# Analysis

As I know attacker injected malware to the host, so I use plugin `windows.pslist` to find any suspicious process. I foudn a suspicious process called `oneetx.exe` with PID `5480` & `5896`.

After searching from the internet ([Oneetx.exe Removal Report](https://www.enigmasoftware.com/oneetxexe-removal/)), I know this is a malware belong to the Trojan `Amedy` family.

Then I use `windows.pstree` to know the process that execute the malware, the malware with PID `5480` was executed when the system start.

```powershell
552     444     wininit.exe     0xad8186f2b080  1       -       0       False   2023-05-21 22:27:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\wininit.exe    -       -
* 696   552     lsass.exe       0xad8186fc6080  10      -       0       False   2023-05-21 22:27:29.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\lsass.exe      C:\Windows\system32\lsass.exe   C:\Windows\system32\lsass.exe
* 676   552     services.exe    0xad8186f4d080  7       -       0       False   2023-05-21 22:27:29.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\services.exe   C:\Windows\system32\services.exe        C:\Windows\system32\services.exe
** 448  676     svchost.exe     0xad8187721240  54      -       0       False   2023-05-21 22:27:41.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe   
*** 5480        448     oneetx.exe      0xad818d3d6080  6       -       1       True    2023-05-21 23:03:00.000000 UTC  N/A    \Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe    -       -
```

Moreoever, the malware with PID `5896` also run a `rundll32.exe` (PID `7732`) process.
<p align="center">
  <img src="./Assets/Image 1 - Malware execure sub process.webp" alt="Malware execure sub process" /> <br />
  <em>Image 1: Malware execure sub process</em>
</p>

And from above, I know the malware is stored in `\Users\Tammam\AppData\Local\Temp\c3912af058\`.

I use plugin `windows.cmdline` to know the command line that run the malware but there is nothing, maybe because the malware was executed when the system start. 

Then, I want to know what the malware did in the system. I will use plugin `windows.netscan` to see the malware connect to C2 server or not. And I found this, the malware connect to the IP `77.91.124.20` in `2023-05-21 23:01:22`.
<p align="center">
  <img src="./Assets/image 2 - Malware connect to C2 server.webp" alt="Malware connect to C2 server" /> <br />
  <em>Image 2: Malware connect to C2 server</em>
</p>

Moreoever, I also found this the suspicious process called `tun2socsk.exe` that ran in about `2023-05-21 23:00`. After searching from the internet ([tun2socks.exe Windows process - What is it?](https://www.file.net/process/tun2socks.exe.html)), I know this file is a part of the software package associated with VPN services called `outline.exe`.
<p align="center">
  <img src="./Assets/Image 3 - VPN process.webp" alt="VPN process" /> <br />
  <em>Image 3: VPN process</em>
</p>

And from the image 2, I know that the IP `33.121.43.65` connect to host through `tun2socks.exe`.

Continue with malware, I use `windows.vadinfo` to know details about memory mappings. So the malware have `PAGE_EXECUTE_READWRITE` protection.
<p align="center">
  <img src="./Assets/Image 4 - Memory mappings of the malware.webp" alt="Memory mappings of the malware" /> <br />
  <em>Image 4: Memory mappings of the malware</em>
</p>

Then I use `strings` and ound that the attacker accessed to these files below. 
<p align="center">
  <img src="./Assets/Image 5 - Attacker access files.webp" alt="Attacker access files" /> <br />
  <em>Image 5: Attacker access files</em>
</p>

# Answer the Questions

**Q1: What is the name of the suspicious process?**

It is `oneetx.exe`.

**Q2: What is the child process name of the suspicious process?**

It is `rundll32.exe`.

**Q3: What is the memory protection applied to the suspicious process memory region?**

It is `PAGE_EXECUTE_READWRITE`.

**Q4: What is the name of the process responsible for the VPN connection?**

It is `outline.exe`.

**Q5: What is the attacker's IP address?**

It is `77.91.124.20`.

**Q6: What is the full URL of the PHP file that the attacker visited?**

It is `http://77.91.124.20/store/games/index.php`.

**Q7: What is the full path of the malicious executable?**

It is `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe `.