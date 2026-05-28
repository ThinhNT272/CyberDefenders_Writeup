# Scenario & Objective

On May 2, 2024, a multinational corporation identified suspicious PowerShell processes on critical systems, indicating a potential malware infiltration. This activity poses a threat to sensitive data and operational integrity.

I have been provided with a memory dump (`memory.dmp`) from the affected system. My task is to analyze the dump to trace the malware's actions, uncover its evasion techniques, and understand its persistence mechanisms.

- **Category**: Endpoint Forensics
- **Tools**: Volatility 3
## Overview

On **May 2, 2024**, a multinational corporation detected suspicious PowerShell processes on their systems. A forensic analysis of the provided memory dump (`memory.dmp`) using Volatility 3 revealed that a suspicious process named **InvolceCheckList.exe**, running under the domain user account **Lee**, spawned two malicious PowerShell processes and a **RegSvcs.exe** process.

To evade detection (MITRE sub-technique **T1562.001**), the malware executed the PowerShell cmdlet **Add-MpPreference** to exclude both **InvolceCheckList.exe** and **HcdmIYYf.exe** from Windows Defender scanning. Additionally, the malware executed **schtasks.exe** to establish persistence on the compromised system.
# Analysis

I was provided a `memory.dmp` and a `windows.psscan_out.txt` files. As I know there is a suspicious PowerShell processes, I check `windows.psscan_out.txt` file and found that there are 2 PowerShell processes with 2 PID `6980`, `7656` with the same PPID (parent process of PID) `4596`.
<p align="center">
  <img src="./Assets/Image 1.1 - PowerShell PID 1.webp" alt="PowerShell PID 1" /> <br />
  <img src="./Assets/Image 1.2 - PowerShell PID 2.webp" alt="PowerShell PID 1" /> <br />
  <em>Image 1: PowerShell PID</em>
</p>

So I check what is process with PID `4596`, there is `InvoiceCheckLi` image file name. Then I filter with `windows.cmdline` plugin to lists process command line arguments. So the `InvolceCheckList.exe` executed suspicious powershell process. 

Moreover, `InvolceCheckList.exe` process use legitimate PowerShell of host through `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` to execute command `Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe"`. Basically, this command add the file `InvoiceCheckList.exe` to the excusion list. The command disables Windows Defender scheduled and real-time scanning for this file.
<p align="center">
  <img src="./Assets/Image 2.1 - Parent Process of PowerShell.webp" alt="Parent Process of PowerShell" /> <br />
  <img src="./Assets/Image 2.2 - Full name of parent process PowerShell.webp" alt="PPID of PowerShell" /> <br />
  <em>Image 2: PPID of PowerShell</em>
</p>

And from the image above, I also know the `InvolceCheckList.exe` also executed `RegSvcs.exe`, `schtasks.exe` in `Windows\Microsoft.NET\Framework\v4.0.30319\` and `Windows\SysWOW64\` respectively.
<p align="center">
  <img src="./Assets/Image 3.1 - Other child processes of suspicious process.webp" alt="Other child processes of suspicious process" /> <br />
  <img src="./Assets/Image 3.2 - Other child processes of suspicious process 2.webp" alt="Other child processes of suspicious process 2" /> <br />
  <em>Image 3: Other child processes of suspicious process</em>
</p>

Then I want to know attacker run any other command in PowerShell with `windows.cmdline` plugin. Beside `InvolceCheckList.exe`, powershell also executed `HcdmIYYf.exe` process.
<p align="center">
  <img src="./Assets/Image 4 - Another command in PowerShell.webp" alt="Another command in PowerShell" /> <br />
  <em>Image 4: Another command in PowerShell</em>
</p>

Then I want to know the who run this process, so I use `windows.getsids` to discover SIDs owning `powershell.exe` process. There are `Administrators` and domain user `Lee` run `powershell.exe` process.
<p align="center">
  <img src="./Assets/Image 5 - SIDs run powershell process.webp" alt="SIDs run powershell process" /> <br />
  <em>Image 5: SIDs run powershell process</em>
</p>
# Answer the Questions

**Q1: Identifying the parent process reveals the source and potential additional malicious activity. What is the name of the suspicious process that spawned two malicious PowerShell processes?**

It is `InvolceCheckList.exe`.

**Q2: By determining which executable is utilized by the malware to ensure its persistence, we can strategize for the eradication phase. Which executable is responsible for the malware's persistence?**

It is `schtasks.exe`.

**Q3: Understanding child processes reveals potential malicious behavior in incidents. Aside from the PowerShell processes, what other active suspicious process, originating from the same parent process, is identified?**

It is `RegSvcs.exe`.

**Q4: Analyzing malicious process parameters uncovers intentions like defense evasion for hidden, stealthy malware. What PowerShell cmdlet used by the malware for defense evasion?**

It is `Add-MpPreference`.

**Q5: Recognizing detection-evasive executables is crucial for monitoring their harmful and malicious system activities. Which two applications were excluded by the malware from the previously altered application's settings?**

It is `InvolceCheckList.exe, HcdmIYYf.exe`.

**Q6: What is the specific MITRE sub-technique ID associated with PowerShell commands that aim to disable or modify antivirus settings to evade detection during incident analysis?**

After researching, I found the sub technique `T1685.001` - Disable or Modify Tools: Disable or Modify Windows Event Log suitable for this situation. But it seems don't match the answer. Then I research again and know in the April - 2026, the MITE ATT&CK updated from v18 to v19 and restructed Impair Defenses techniques `T1562` into technique `T1685` and related techniques.

So the correct answer is `T1562.001`.

**Q7: Determining the user account offers valuable information about its privileges, whether it is domain-based or local, and its potential involvement in malicious activities. Which user account is linked to the malicious processes?**

It is domain user `Lee`.