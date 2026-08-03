# Scenario & Objective

As a cybersecurity analyst at TechSecure Corp, you have been alerted to unusual activities within the company's Active Directory environment. Initial reports suggest unauthorized access and possible privilege escalation attempts.

Your task is to analyze the provided logs to uncover the attack's extent and identify the malicious actions taken by the attacker. Your investigation will be crucial in mitigating the threat and securing the network.

- **Category**: Threat Hunting
- **Tools**: Splunk, VirusTotal

## Overview

On August 6, 2024, an attacker compromised the `CORPNET` Active Directory environment, conducting credential harvesting, privilege escalation, and lateral movement across `Office-PC` and `FileServer`. At `01:05`, the intrusion began on `Office-PC` when a malicious executable named `AdobeUpdater.exe` (PID `3540`) was executed from `C:\Users\sanderson\Downloads\` under the account `CORPNET\sanderson`. `AdobeUpdater.exe` spawned a command prompt that ran a PowerShell execution policy bypass (`powershell -ep bypass`) to launch `BackupUtility.exe` (PID `2304`, identified as `Rubeus`).

At `01:07`, `AdobeUpdater.exe` dropped additional malicious tools into `C:\Users\Default\AppData\Local\Temp\`, including `DefragTool.exe` (identified as `Mimikatz`) and `SystemDiagnostics.ps1`. To maintain persistence, the attacker created a registry Run key named `wyW5PZyF` under `HKU\S-1-5-21-1096375878-1107820087-318151060-1105\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\`. Using `Rubeus` for Kerberoasting, the attacker successfully harvested the credentials for domain user `CORPNET\tcooper`. At `01:14`, the attacker executed `Mimikatz` (`DefragTool.exe`) under the `tcooper` account for credential dumping and Active Directory manipulation.

At `01:17`, the attacker enabled Remote Desktop Protocol (RDP) on remote systems by running `reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0`. Following initial network logons (logon type 3), the attacker established an interactive RDP session (logon type 10) on `FileServer` at `01:19:20` as `CORPNET\tcooper`. Once inside `FileServer`, the attacker collected confidential data and compressed the files into an archive named `CrashDump.zip`.

# Analysis

Follow the scenario that there is possible privilege escalation attempts, while the system has 3 sources as image 1. Based on the name, I think that the attacker can have initial access into `Office-PC`, then he perform attack to high-value target like `DC01` and `FileServer`, this cause the privilege escalation action. Follow this way, I filter with unusual activities in the `Office-PC` host.
<p align="center">
  <img src="./Assets/Image 1 - Sources in the system.png" alt="Sources in the system"/><br/>
  <em>Image 1: Sources in the system</em>
</p>

To find the unusual actions I filter with sysmon ID 1 - process creation. Then I found that at about `08-06-2024 01:05`, there is a suspicious process `AdobeUpdater.exe` (PID 3540) because it is in the `\Downloads\` folder of user `sanderson` (`C:\Users\sanderson\Downloads\`), while the legitimate folder of this process is `C:\Program Files\Adobe\` or `C:\Program Files (x86)\Adobe\`. I also check hash of this file in VirusTotal but nothing special.
```SPl
index=shadowroast source="C:\\Logs\\Office-PC.ndjson" "event.code"=1
| eval Hashes = replace('winlog.event_data.Hashes', ",", ", ")
| rename winlog.event_data.ParentProcessId as PPID, winlog.event_data.ProcessId as PID
| table @timestamp, winlog.event_data.ParentCommandLine, PPID, winlog.event_data.CommandLine, PID, Hashes
```
<p align="center">
  <img src="./Assets/Image 2 - Suspicious process.png" alt="Suspicious process"/><br/>
  <em>Image 2: Suspicious process</em>
</p>

However, this file is still a malware because this file create a cmd process, run the command `powershell -ep bypass` - bypass Execution Policy to run any script - and run malicious file `BackupUtility.exe` (PID 2304) also know as `Rubeus.exe`. Moreover, this file is run by the first compromised account `CORPNET\sanderson`.
<p align="center">
  <img src="./Assets/Image 3.1 - Verify malware.png" alt="Verify malware"/><br/>
  <img src="./Assets/Image 3.2 - Suspicious process.png" alt="Suspicious process"/><br/>
  <em>Image 3: Malicious dropped</em>
</p>

Based on the timestamp, this malicious file surely downloaded by `AdobeUpdater.exe`, but I still need to verify that by event ID 11 - File Create. At about `01:07`, beside `BackupUtility.exe` (`Rubeus.exe`), the file `AdobeUpdater.exe` also created `DefragTool.exe` (`mimikatz.exe`) and `SystemDiagnostics.ps1` script.
```SPL
index=shadowroast source="C:\\Logs\\Office-PC.ndjson" "event.code"=11
| table @timestamp, winlog.event_data.Image, winlog.event_data.TargetFilename, winlog.event_data.ProcessId
```
<p align="center">
  <img src="./Assets/Image 4.1 - All malicious dropped files.png" alt="All malicious dropped files"/><br/>
  <img src="./Assets/Image 4.2 - Verify mimikatz tool.png" alt="Verify mimikatz tool"/><br/>
  <em>Image 4: Every dropped files</em>
</p>

Then he run the `mimikatz.exe` at about `01:14`. As I know, `mimikatz.exe` is a tool that be used to dump credential to perform Pass-the-Hash technique. The tool is run by compromised account `CORPNET\tcooper`. I think this account is compromised by the tool `Rubeus.exe` above.
<p align="center">
  <img src="./Assets/Image 5 - Attacker run malicious mimikatz tool.png" alt="Attacker run malicious mimikatz tool"/><br/>
  <em>Image 5: Attacker run malicious mimikatz tool</em>
</p>

Both tools are used for Lateral Movement technique (T1550) that move from low priviledge endpoint to high value host using stolen credential. And both compromised account have eventID 4672 (Special privileges assigned to new logon), which suitable with "privilege escalation attempts" of scenario.

I also check the sysmon ID 7 - Image Loaded - to find any suspicious DLL file that the malware inject. But the malware just run some legitimate DLL file of windows.

Moreover, attacker usually do something so that he can stay persistent in the system. So I need to check all sysmon ID that can detect access persistent, it is event ID 12 (RegistryEvent - Object create and delete) and 13 (RegistryEvent - Value Set). 
<p align="center">
  <img src="./Assets/Image 6 - Persistence attack via registry.png" alt="Persistence attack via registry"/><br/>
  <em>Image 6: Persistence attack via registry</em>
</p>

Then I found there is only 1 event with sysmon ID 13 about malicious `AdobeUpdater.exe`. The attacker set the registry key `HKU\S-1-5-21-1096375878-1107820087-318151060-1105\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\wyW5PZyF` to ensures that the program runs every time the user logs on to the system.

That is all information I can find in the host `Office-PC`. Then follow the time line, there are multiple login attemp of compromised account `tcooper` with login type 3 - network logon - which is strong indicator of attack. Beside that, at about `01:19:20`, there is a logon type 10, which indicates a remote Interactive logon like Remote Desktop Protocol (RDP).
<p align="center">
  <img src="./Assets/Image 7.1 - Suspicious logon type 3.png" alt="Suspicious logon type 3"/><br/>
  <img src="./Assets/Image 7.2 - Suspicious logon type 10.png" alt="Suspicious logon type 10"/><br/>
  <em>Image 7: Suspicious login actions</em>
</p>

He can access with logon type 10 because at about `01:17`, attacker turn the RDP service on by change the value of registry `"C:\Windows\system32\reg.exe" add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0`.
<p align="center">
  <img src="./Assets/Image 8 - Turn on RDP via registry.png" alt="Turn on RDP via registry"/><br/>
  <em>Image 8: Turn on RDP via registry</em>
</p>

Moreover, attacker also create some suspicious file in the server, but I don't know which process create that. I also check the sysmon ID 1 but these PS1 files were not executed. And based on the name, I think `CrashDump.zip` is just a file that contain all the information that the attacker extracted.
<p align="center">
  <img src="./Assets/Image 9 - Suspicious files in service server.png" alt="Suspicious files in service server"/><br/>
  <em>Image 9: Suspicious files in service server</em>
</p>

The same thing happend with host DC01, attacker also turn on the RDP service but there is no login attemp. I also cannot any suspicious file in the DC01 host.

# Answer the Questions

**Q1: What's the malicious file name utilized by the attacker for initial access?**

It is `AdobeUpdater.exe`.

**Q2: What's the registry run key name created by the attacker for maintaining persistence?**

It is `wyW5PZyF`.

**Q3: What's the full path of the directory used by the attacker for storing his dropped tools?**

From the image 4 above, the full path is `C:\Users\Default\AppData\Local\Temp\`.

**Q4: What tool was used by the attacker for privilege escalation and credential harvesting?**

It is `Rubeus`.

**Q5: Was the attacker's credential harvesting successful? If so, can you provide the compromised domain account username?**

Yes, the compromised domain account username is `tcooper`.

**Q6: What's the tool used by the attacker for registering a rogue Domain Controller to manipulate Active Directory data?**

It is `Mimikatz`.

**Q7: What's the first command used by the attacker for enabling RDP on remote machines for lateral movement?**

The correct format is `reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0`.

**Q8: What's the file name created by the attacker after compressing confidential files?**

It is `CrashDump.zip`.