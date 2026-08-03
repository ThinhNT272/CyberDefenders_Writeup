# Scenario & Objective

A multinational corporation has suffered a cyber attack, resulting in the theft of sensitive data. The attack employed a previously unseen variant of the BlackEnergy v2 malware. The company's security team has obtained a memory dump from the infected machine and is seeking your expertise as a SOC analyst to analyze the dump in order to understand the scope and impact of the attack.

- **Category**: Endpoint Forensics
- **Tools**: Volatility 3

## Overview

On February 13, 2023, forensic analysis of a Windows XP memory image revealed a malware infection involving BlackEnergy v2 rootkit. The execution sequence began at `17:54:18 UTC`, when `explorer.exe` (PID `1440`) spawned `explorer.exe` (PID `1484`). At `18:25:26 UTC`, the malicious binary `rootkit.exe` (PID `964`) was launched from `C:\Documents and Settings\CyberDefenders\Desktop\rootkit.exe`, subsequently spawning a command prompt `cmd.exe` (PID `1960`).

Following execution, `rootkit.exe` performed process injection into the legitimate system process `svchost.exe` (PID `880`) at base address `0x980000`, indicated by an unmapped `MZ` header in memory. To achieve stealthy rootkit persistence, the injected `svchost.exe` process loaded a kernel driver `C:\WINDOWS\system32\drivers\str.sys` and unhooked `msxml3r.dll` to hide it from standard module lists (`InLoad`, `InInit`, `InMem`). At `18:29:08 UTC`, the memory capture tool `DumpIt.exe` (PID `276`) was executed from the desktop to acquire system memory for analysis.

# Analysis

First, I want to know some information about the RAW file, so I use plugin `windows.info`.
<p align="center">
  <img src="./Assets/Image 1 - Host infor.png" alt="Host infor" /> <br />
  <em>Image 1: Host infor</em>
</p>

Based on the information above, the host is `WindowsXPSP3x86`. But the timestamp is `13 April 2008` while the service pack 3 was released to manufacturing on `21 April 2008`. So the service pack is 2 or 3. 

Among `19` processes, I found two suspicious process `rootkit.exe` and `DumpIt.exe`.
```vol3
PID     PPID    ImageFilename   CreateTime    Patdh

1484    1440    explorer.exe    2023-02-13 17:54:18.000000 UTC    C:\WINDOWS\Explorer.EXE

* 964   1484    rootkit.exe     2023-02-13 18:25:26.000000 UTC  \Device\HarddiskVolume1\Documents and Settings\CyberDefenders\Desktop\rootkit.exe
  
** 1960 964     cmd.exe         2023-02-13 18:25:26.000000 UTC    \Device\HarddiskVolume1\WINDOWS\system32\cmd.exe
  
* 276   1484    DumpIt.exe      2023-02-13 18:29:08.000000 UTC    C:\Documents and Settings\CyberDefenders\Desktop\dumpit-moonsols\DumpIt.exe
```

Then I want to know these suspicious processes connect to C2 server or not. But the plugin `netscan` and `netstat` is not supported. At this time, I have no idea to find, so I use some question as hints. 

For answering the question 5, I use plugin `windows.malfind` to lists process memory ranges that potentially contain injected code. Then I found some processes like `csrss.exe`, `winlogon.exe`, `svchost.exe` and `msmsgs.exe`.

But the `svchost.exe` process with PID `880` and base address `0x980000` demonstrates clear signs of code injection, and one of the most significant indicators is the presence of the `4D 5A` hexadecimal sequence within its memory. This sequence corresponds to the ASCII characters `MZ`. The `MZ` header is the starting signature of PE files, indicating the beginning of an executable or DLL.
<p align="center">
  <img src="./Assets/Image 2 - Potentially injected code process.png" alt="Potentially injected code process" /> <br />
  <em>Image 2: Potentially injected code process</em>
</p>

Then for the question 6, to identify an odd file associated with a specific process, I use the `windows.handles` plugin to enumerates all open handles of a given process or all processes, showing references to system resources such as files, registry keys, events, and threads. 
<p align="center">
  <img src="./Assets/Image 3 - Odd files.png" alt="Odd files" /> <br />
  <em>Image 3: Odd files</em>
</p>

So the process with PID `880` references the file `\Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys`.

For answering question 7, I use plugin `windows.ldrmodules` to examines the loaded modules (DLLs) within a specific process and categorizes them into three key lists: `InLoad`, `InInit`, and `InMem`. These lists correspond to whether a DLL is visible in the process’s load list, initialization list, or memory mapping. Then I found the suspicious DLL `msxml3r.dll` that is loaded by `svchost.exe` process. Moreover, it is `False` in the `InLoad`, `InInit`, and `InMem` columns. This is highly suspicious because injected DLLs often bypass normal loading mechanisms, making them invisible in one or more of these categories.
<p align="center">
  <img src="./Assets/Image 4 - Suspicious DLL file.png" alt="Suspicious DLL file" /> <br />
  <em>Image 4: Suspicious DLL file</em>
</p>

# Answer the Questions

**Q1: Which volatility profile would be best for this machine?**

However my answer is `WindowsXPSP3x86` but it seems wrong. So I switch to answer `WindowsXPSP2x86` and it correct.

**Q2: How many processes were running when the image was acquired?**

There are `19` processes.

**Q3: What is the process ID of `cmd.exe`?**

It is `1960`.

**Q4: What is the name of the most suspicious process?**

It is `rootkit.exe` or `DumpIt.exe`. But `rootkit.exe` seems like match the answer.

**Q5: Which process shows the highest likelihood of code injection?**

It is `svchost.exe`.

**Q6: There is an odd file referenced in the recent process. Provide the full path of that file.**

The odd file referenced in the `svchost.exe` process is `\Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys` but it is not match the format. So the final answer that match format is `C:\WINDOWS\system32\drivers\str.sys`.

**Q7: What is the name of the injected DLL file loaded from the recent process?**

It is `msxml3r.dll`.

**Q8: What is the base address of the injected DLL?**

It is `0x980000`.