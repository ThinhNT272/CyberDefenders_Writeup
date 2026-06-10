# Scenario & Objective

You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users have reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.

- **Category**: Threat Hunting
- **Tools**: Splunk, VirusTotal

## Overview

On **September 7, 2023**, a host on the client network was compromised by the **REvil** (Sodinokibi) ransomware gang. The attack progressed through the following sequence of events:

At `04:09:50 PM`, the ransomware loader `facebook assistant.exe` (PID `5348`, SHA256: `B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA`) was executed from the Administrator downloads folder.

Then at `04:09:53 PM`, the loader spawned a PowerShell process (PID `1860`) running an encoded script that decoded to `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}`. This deleted all system volume shadow copies to prevent file recovery.

At about `04:10 PM` the ransomware encrypted user files and left ransom notes named `5uizv5660t-readme.txt` across directories. Forensic threat intelligence linked the operations to the C2 payment and decryption onion domain: `aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion`.

After that, at `04:11:08 PM`, the parent loader process terminated itself (`event.code=5`) - a part of common malware's lifecycle - leaving background processes to complete the encryption phase.

# Analysis

The Splunk contains the event from `2023-09-07 15:12:19` to `2023-09-08 04:24:35`. At first, I check all source in splunk and I have:

- 1 host: Windows
- 1 source: winlog.ndjson
- 1 source type: REvil

> `REvil` is the name of the ransomeware that was operated by `Sodinokibi` - one of the world's most notorious Russian-speaking ransomware gangs.

As I know the clients system was affected by a ransomeware called `REvil`, I need to find the directory that store the malware by checking the command executed.

```SPL
index=* "log.file.path"="C:\\evtx\\Sysmon.evtx"
| stats count by winlog.event_data.ParentCommandLine
```

There a suspicious process `C:\Users\Administrator\Downloads\facebook assistant.exe` and suspicious script `C:\Program Files\Graphviz\Clear_Event_Viewer_Logs.bat`. 
<p align="center">
  <img src="./Assets/Image 1 - Suspicious files.webp" alt="Suspicious files" /> <br />
  <em>Image 1: Suspicious files</em>
</p>

At first, I follow the `facebook assistant.exe` file. 

```SPL
index=* "facebook assistant.exe"
```

Then, I found the field `winlog.event_data.TargetFilename` - specific field that captures the full file path and name of a file being created, modified, deleted, or renamed by a process `facebook assistant.exe`.

After querying, at about `04:10 PM` there are so many file `5uizv5660t-readme.txt` was created (`event.code=11`) by malicious process and was stored in various directory. Based on the name of the file, I can know there are ransom notes - which guide user to pay for their documents. 
<p align="center">
  <img src="./Assets/Image 2 - Ransom notes.webp" alt="Ransom notes" /> <br />
  <em>Image 2: Ransom notes</em>
</p>

Moreoever, there are 5 values of `event.code` as below:

| Event.code value | Description                                                                                                                                       | Count of events |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| 1                | **Process Creation**: Logs the launch of a new process, captures critical metadata such as command-line path, the parent process, process hashes. | 2               |
| 5                | **Process Terminated**: Logs when a process ends.                                                                                                 | 1               |
| 7                | **Image Loaded**: Records when a module (such as a `.dll` file) is loaded into a specific process.                                                | 1               |
| 11               | **File Create**: Logs when a file is created or overwritten.                                                                                      | 21              |
| 13               | **Registry Event**: Logs changes or assignments to Windows Registry values.                                                                       | 1               |

So, I follow the `event.code=1` to find all processes that be created.

```SPL
index=* "facebook assistant.exe" event.code=1
| table winlog.event_data.CommandLine, winlog.event_data.ParentCommandLine, winlog.event_data.Hashes, winlog.event_data.ProcessId
```

| Time                          | winlog.event_data.CommandLine                                                                                                                                                              | winlog.event_data.ParentCommandLine                       | winlog.event_data.Hashes                                                                                                                                                                                     | winlog.event_data.ProcessId |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- |
| 09/07/23  <br>04:09:53.578 PM | powershell -e RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAY<br>wB0ACAAewAkAF8ALgBEAGUAbABlAHQAZQAoACkAOwB9AA== | "C:\Users\Administrator\Downloads\facebook assistant.exe" | SHA1=6CBCE4A295C163791B60FC23D285E6D84F28EE4C<br>MD5=7353F60B1739074EB17C5F4DDDEFE239<br>SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C<br>IMPHASH=741776AACCFC5B71FF59832DCDCACE0F | 1860                        |
| 09/07/23  <br>04:09:50.836 PM | "C:\Users\Administrator\Downloads\facebook assistant.exe"                                                                                                                                  | C:\Windows\Explorer.EXE                                   | SHA1=E5D8D5EECF7957996485CBC1CDBEAD9221672A1A<br>MD5=4D84641B65D8BB6C3EF03BF59434242D<br>SHA256=B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA<br>IMPHASH=C686E5B9F7A178EB79F1CF16460B6A18 | 5348                        |

I check hash of 2 processes, the first one just a powershell, nothing special, but the second one (`facebook assistant.exe`) is flagged as malicious by `66/71` vendors. Moreover, I also know the PID of malware is `5348`.
<p align="center">
  <img src="./Assets/Image 3 - Verify revil ransomware.webp" alt="Verify revil ransomware" /> <br />
  <em>Image 2: Verify revil ransomware</em>
</p>

Moreover, after research and know the command `powershell -e <string>` is base64 encode. So I decoded the string and get this command `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}`. This is command will delete all shadow copy in windows systems. It is exactly what the ransomware do so that they can encrypt datas and get paid from victim.

Then at about `04:09:50.852 PM`, the malicious file was running (`event.code=7`).
<p align="center">
  <img src="./Assets/Image 4 - Malicious loaded file.webp" alt="Malicious loaded file" /> <br />
  <em>Image 4: Malicious loaded file</em>
</p>

Then with `event.code=13`, at about `04:09:53.577 PM`, the malicious is added into registry `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-2931289057-395607685-1339121393-500\\Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. This is normal action that windows system automatically added this registry when process was running by BAM (Background Activity Moderator) feature. 

With `event.code=5`, at about `04:11:08.091 PM`, the malware was terminated. But it doesn't mean the malware was removed, it just a part of malware lifecycle. The initial executable, `facebook assistant.exe`, acts as a loader/dropper - a standard malware tactic. It invokes legitimate system binaries like `powershell.exe` to perform critical malicious actions, such as removing shadow copies. After spawning these child processes or injecting code into system processes, the parent process kills itself to minimize its footprint in Task Manager. The background child processes then proceed with the file encryption phase uninterrupted

Finallly, another common tactic is used by malware is connect to C2 server. I use the SHA256 hash above in `tria.ge` to access detail behavioral reports about the malware's activities.
<p align="center">
  <img src="./Assets/Image 5 - C2 server.webp" alt="C2 server" /> <br />
  <em>Image 5: C2 server</em>
</p>

Then I found the C2 server `http://aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion`, this  domains are indicators of ransomware operations, as they allow attackers to maintain anonymity while coordinating payments and providing decryption keys to victims.

# Answer the Questions

**Q1: To begin your investigation, can you identify the filename of the note that the ransomware left behind?**

Ransom note is `5uizv5660t-readme.txt`.

**Q2: After identifying the ransom note, the next step is to pinpoint the source. What's the process ID of the ransomware that's likely involved**

It is `5348`.

**Q3: Having determined the ransomware's process ID, the next logical step is to locate its origin. Where can we find the ransomware's executable file?**

It is `C:\Users\Administrator\Downloads\facebook assistant.exe`.

**Q4: Now that you've pinpointed the ransomware's executable location, let's dig deeper. It's a common tactic for ransomware to disrupt system recovery methods. Can you identify the command that was used for this purpose?**

The command is `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}`.

**Q5: As we trace the ransomware's steps, a deeper verification is needed. Can you provide the sha256 hash of the ransomware's executable to cross-check with known malicious signatures?**

Sha256 hash value of ransomeware is `B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA`.

**Q6: One crucial piece remains: identifying the attacker's communication channel. Can you leverage threat intelligence and known Indicators of Compromise (IoCs) to pinpoint the ransomware author's onion domain?**

It is `aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion` because it matches with the answer format.