# Scenario & Objective

As a cybersecurity analyst at SecureTech Industries, you've been alerted to unusual login attempts and unauthorized access within the company's network. Initial indicators suggest a potential brute-force attack on user accounts. Your mission is to analyze the provided log data to trace the attack's progression, determine the scope of the breach, and the attacker's TTPs.

- **Category**: Threat Hunting
- **Tools**: Splunk, IP Location

## Overview

The incident occurs in `2024-09-09`, the attacker from `Helsinki`, `Findland` with IP 
`77.91.78.115` access the system via brute-force technique.

For more detail, at `16:55` to `16:56`, attacker brute-force attack to host `ST-WIN02`. After successfully authenticates to `ST-WIN02` using credentials of `mwilliams` and `michaelwilliams`, at about `17:17` attacker configures registry persistence on victim,  everytime the victim startup, it will execute the `OfficeUpdater.exe` file located in `C:\Windows\Temp\` folder.

Then, from `17:27`, attacker executed `miimkatz.exe` (PID `3708`) in `C:\Users\Public\Backup_Tools` folder. After that, at about `17:34`, attacker performs lateral movement to `ST-DC01` using the credentials of `jsmith` account. Moreover, I found the event code 4769, which indicates a Kerberos service ticket, so I assume that attacker access `ST-DC01` using Kerberoasting technique.

In the DC, at `17:38`, attacker set scheduled task called `FilesCheck`. This `FilesCheck` task will execute `FileCleaner.exe` via powershell every hour with highest permission.

At about `17:50`, the attacker logs in to `ST-FS01` still using `jsmith` credentials, creating a file `Archive_8673812.zip` in `C:\Users\Public\Documents\` folder. Based on the name of the file, I assume that the file contains information that the attacker extracted.

# Analysis

The lab already give me `index=goldenspray`, so I just follow this index. It seems like the unusual access actions are carried out by 1 or more  of the following hosts.
<p align="center">
  <img src="./Assets/Image 1 - All hosts.png" alt="All hosts" /> <br />
  <em>Image 1: All hosts</em>
</p>

As I know these logs come from Window host, and follow the failed login attempts from the scenario, I filter with event code `4625` to find all the failed login actions. There are 34 host, still from 4 hosts above.

I want to narrow down to specific hosts, so I filter with this:

```
index=goldenspray event.code=4625
| table _time, event.provider, host, winlog.event_data.IpAddress, winlog.event_data.TargetUserName
```
<p align="center">
  <img src="./Assets/Image 2 - Suspicious host.png" alt="Suspicious host" /> <br />
  <em>Image 2: Suspicious host</em>
</p>

In `2024-09-09`, at about `16:55:16` to `16:56:05` time, there are about 15 events failed login from public  IP `77.91.78.115` to the host `ST-WIN02` with multiple username. This indicates that suspicious IP `77.91.78.115` using tool try to brute force into host `ST-WIN02`.

Next, follow the scenario "unauthorized access", I want to know which usernames do the suspicious IP use to access which host, so I filter with IP above and event code `4624`. There is only 10 events now.

```
index=goldenspray event.code=4624 winlog.event_data.IpAddress=77.91.78.115
| table _time, host, winlog.event_data.TargetUserName, winlog.event_data.WorkstationName, winlog.event_data.IpPort, winlog.event_data.AuthenticationPackageName
```
<p align="center">
  <img src="./Assets/Image 3 - Unauthorized access.png" alt="Unauthorized access host" /> <br />
  <em>Image 3: Unauthorized access</em>
</p>

At about `16:56 - 17:00`, attacker access victim `ST-WIN02` with username `mwilliams` and `michaelwilliams`. At about `17:34`, attacker use username `jsmith` to access host `ST-DC01`. Then, attacker login to `ST-FS01` still using `jsmith` account at about `17:50`. Moreover, he also use `kali` - which is common machine that usually be used for attacking.

At first, I want to know what did attacker do in the host `ST-WIN02`. With the username `michaelwilliams`, there are nothing special, adversary just login and do nothing. So I filter with username `mwilliams` and after specific time `17:00`, there are multiple actions. 
<p align="center">
  <img src="./Assets/Image 4.1 - Specific of time.png" alt="Specific of time" /> <br />
  <img src="./Assets/Image 4.2 - Event code of attacker.png" alt="Event code of attacker" /> <br />
  <em>Image 4: Attacker activities</em>
</p>

Here is a brief description of those event code above (from this: [Randy's Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)):

- `1 - Process creation`: This provides extended information about a newly created process.
- `2 - A process changed a file creation time`: This event helps tracking the real creation time of a file.
- `3 - Network connection detected`: The network connection event logs TCP/UDP connections on the machine.
- `5 - Process terminated`: This reports when a process terminates.
- `7 - Image loaded`: The image loaded event logs when a module is loaded in a specific process.
- `11 - FileCreate`: This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.
- `12 - RegistryEvent (Object create and delete)`: Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations, or specific malware registry modifications.
- `13 - RegistryEvent (Value Set)`: This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD.
- `17 - Pipe created`: This event shows the creation of named pipes on the server side of the pipe
- `22 - DNSEvent`: This event allows you to monitor the query and results sent back by the DNS server as well as the process that generated the query.
- `23 - FileDelete`: This event creates an opportunity to hold on to malware files or data staged for exfiltration even when they delete it.
- `29 - File Executable Detected`: This is a valuable event for detecting the appearance of new EXEs and DLLs on your network.

First, I check for process creation (event id = 1) to know what did attacker do..

```
index=goldenspray host="st-win02" "winlog.event_data.User"="SECURETECH\\mwilliams" event.code=1
| table _time, winlog.event_data.CommandLine, winlog.event_data.ProcessId, winlog.event_data.Hashes
```
<p align="center">
  <img src="./Assets/Image 5.1 - Attacker create files 1.png" alt="Attacker create files 1" /> <br />
  <img src="./Assets/Image 5.2 - Attacker create files 2.png" alt="Attacker create files 2" /> <br />
  <em>Image 5: Event code no 1</em>
</p>

At about `17:17:09`, attacker use command `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v OfficeUpdater /t REG_SZ /d "C:\Windows\Temp\OfficeUpdater.exe" /f`, this command adds a startup entry to the Windows Registry. Every time the computer boots up, the operating system will automatically execute the file located at `C:\Windows\Temp\OfficeUpdater.exe` with administrative privileges. This file is quite suspicious because the process run in `\Temp` folder while the legitimate office update file is usually located at `C:\Program Files\Common Files\microsoft shared\ClickToRun`. I also check the hash in VirusTotal but it seems like nothing special.

Moreover, at `17:27`, attacker run `mimikatz.exe` in `C:\Users\Public\Backup_Tools` folder. Mimikatz is an open-source tool designed to find and dump authentication data from Windows system memory. This tools is usually used in Pass the Hash or Kerberoasting attack. 

The `mimikatz.exe` have the PPID `6248`, which is the script `C:\Users\mwilliams\AppData\Local\Temp\__PSScriptPolicyTest_tdeh0il4.y52.ps1`. The ps1 script run the command as below.
```cmd
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Set-Location -literalPath 'C:\Users\Public\Backup_Tools'
```

And you can see that the first time hacker run mimikatz (with PID `3708`) tool is at `17:27` and at `17:34` (look at image 3 above) there is a login action of `jsmith` to `ST-DC01`. Based on the timeline, I assume that attacker got the `jsmith` credentials from `ST-WIN02` and attack DC through Pass the Hass or kerberoasting techniques. To identify exactly what technique that the attacker use, I check for event code 4769 - a Kerberos service ticket was requested. 
<p align="center">
  <img src="./Assets/Image 6 - Kerberos encryption.png" alt="Kerberos encryption" /> <br />
  <em>Image 6: Kerberos encryption</em>
</p>

The system use Keberos encryption `0x17`, which is `RC4` algorithm. This is an old encryption that can be offline crack. So I can say attack got `jsmith` credentials through Kerberoasting attack.
<p align="center">
  <img src="./Assets/Image 7 - CR4 algorithm.png" alt="CR4 algorithm" /> <br />
  <em>Image 7: CR4 algorithm</em>
</p>

Moreover, when I filter with event id equal 11, I found that beside process `OfficeUpdater.exe` and mimikatz, attacker also run some process like `PsExec.exe` or `PowerView.ps1`.
<p align="center">
  <img src="./Assets/Image 8 - Other malicious processes.png" alt="Other malicious processes" /> <br />
  <em>Image 8: Other malicious processes</em>
</p>

That is all information I can found in username `mwilliams`. Now switch to account `jsmith`. Based on the timeline I said above, I filter `jmith` in host `ST-DC01` since `17:34`. There are 142 events with 10 event IDs exist.
<p align="center">
  <img src="./Assets/Image 9 - Event ID in DC by attacker.png" alt="Event ID in DC by attacker" /> <br />
  <em>Image 9: Event ID in DC by attacker</em>
</p>

I filter with event ID 1, I found this command `schtasks /create /tn "FilesCheck" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\FileCleaner.exe" /sc hourly /ru SYSTEM`. This command set scheduled task called `FilesCheck`. This `FilesCheck` task will execute `FileCleaner.exe` via powershell every hour with highest permission.
<p align="center">
  <img src="./Assets/Image 10 - Scheduled task.png" alt="Scheduled task" /> <br />
  <em>Image 10: Scheduled task</em>
</p>

Next, attacker also access `ST-FS01` using `jsmith` account since `17:50`.
<p align="center">
  <img src="./Assets/Image 11 - Event ID in FS01 by attacker.png" alt="Event ID in FS01 by attacker" /> <br />
  <em>Image 11: Event ID in FS01 by attacker</em>
</p>

When filtering with event id 11, I found that attacker create some scripts `__PSScriptPolicyTest_qagno2xr.jow.ps1`, `__PSScriptPolicyTest_gpvuqvvq.rpi.ps1` and file `Archive_8673812.zip`.
<p align="center">
  <img src="./Assets/Image 12 - Files cerated by attacker.png" alt="Files cerated by attacker" /> <br />
  <em>Image 12: Files cerated by attacker</em>
</p>

Then attacker deletes those script (event ID 23), this action make the scritp so suspicious.
<p align="center">
  <img src="./Assets/Image 13 - Files are deleted.png" alt="Files are deleted" /> <br />
  <em>Image 13: Files are deleted</em>
</p>

# Answer the Questions

**Q1: What is the attacker's IP address?**

Attacker's IP address is `77.91.78.115`.

**Q2: What country is the attack originating from?**

Attacker come from `Helsinki, Findland`.
<p align="center">
  <img src="./Assets/Image 14 - Attacker location.png" alt="Attacker location" /> <br />
  <em>Image 14: Attacker location</em>
</p>

**Q3: What's the compromised account username used for initial access?**

It is `mwilliams` because the username `michaelwilliams` don't have any suspicious actions.

**Q4: What's the name of the malicious file utilized by the attacker for persistence on `ST-WIN02`?**

It is `OfficeUpdater.exe`.

**Q5: What is the complete path used by the attacker to store their tools?**

The full path is `C:\Users\Public\Backup_Tools`.

**Q6: What's the process ID of the tool responsible for dumping credentials on `ST-WIN02`?**

The process `mimikatz.exe` has an ID `3708`.

**Q7: What's the second account username the attacker compromised and used for lateral movement?**

It is `jsmith`.

**Q8: Can you provide the scheduled task created by the attacker for persistence on the domain controller?**

It is `OfficeUpdater.exe`.

**Q9: What type of encryption is used for Kerberos tickets in the environment?**

The system uses `0x17` or `RC4` encryption.

**Q10: Can you provide the full path of the output file in preparation for data exfiltration?**

It is `C:\Users\Public\Documents\Archive_8673812.zip`.