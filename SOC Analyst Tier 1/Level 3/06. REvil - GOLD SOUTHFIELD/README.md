# Scenario & Objective

You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users have reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.

- **Category**: Threat Hunting
- **Tools**: Splunk, VirusTotal

## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

First, I check all source in splunk and I have:

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

After querying, there are so many file `.txt` was created (`event.code=11`) by malicious process and was stored in various directory. Based on the name of the file, I can know there are ransom notes - which guide user to pay for their documents. 
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

Then at about `4:09:50.852 PM`, the malicious file loaded a file (`event.code=7`).
<p align="center">
  <img src="./Assets/Image 4 - Malicious loaded file.webp" alt="Malicious loaded file" /> <br />
  <em>Image 4: Malicious loaded file</em>
</p>

Then with `event.code=13`, at about `4:09:53.577 PM`, the malicious add into registry `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-2931289057-395607685-1339121393-500\\Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` for persistent compromised.

Finally with `event.code=5`, at about `4:11:08.091 PM`, the malicious terminate `...` process.
![[README-1780567346956.webp]]
![[README-1780567380941.webp]]
![[README-1780567394493.webp]]

# Answer the Questions

Code sample for image:
<p align="center">
  <img src="./Assets/abc.webp" alt="abc" /> <br />
  <em>Image 1: abc</em>
</p>