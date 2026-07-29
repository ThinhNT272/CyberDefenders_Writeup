# Scenario & Objective

As a member of the DFIR team at SecuTech, you're tasked with investigating a security breach affecting multiple endpoints across the organization. Alerts from different systems suggest the breach may have spread via removable devices. You’ve been provided with a memory image from one of the compromised machines. Your objective is to analyze the memory for signs of malware propagation, trace the infection’s source, and identify suspicious activity to assess the full extent of the breach and inform the response strategy.

- **Category**: Endpoint Forensics
- **Tools**: MemProFS, VirusTotal

Code sample for image:
<p align="center">
  <img src="./Assets/abc.png" alt="abc"/><br/>
  <em>Image 1: abc</em>
</p>

## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

As I have `memory.dmp` file, I will use tools in `Memory Analysis` category. First, I use `volatility 3` but I cannot find any suspicious process. And I have no idea to continue. So I follow the official writeup and questions as a guide.
# Answer the Questions

**Q1: Tracking the serial number of the USB device is essential for identifying potentially unauthorized devices used in the incident, helping to trace their origin and narrow down your investigation. What is the serial number of the inserted USB device?**

The writeup guide me to use MemProFS tool in "Memory Analysis" to mount memory images as virtual file systems. 
<p align="center">
  <img src="./Assets/Image 1.1 - Execute MemProFS tool.png" alt="Execute MemProFS tool"/><br/>
  <img src="./Assets/Image 1.2 - Successfull mount process.png" alt="Successfull mount process"/><br/>
  <em>Image 1: Mount memory file</em>
</p>

According to [MemProcFS/files/plugins/pyp_reg_root_reg$usb_usb$devices.py at master · ufrisk/MemProcFS · GitHub](https://github.com/ufrisk/MemProcFS/blob/master/files/plugins/pyp_reg_root_reg$usb_usb$devices.py), I can find the USB device information in the path `HKLM\\SYSTEM\\ControlSet001\\Enum\\USB`. 
<p align="center">
  <img src="./Assets/Image 2 - USB serial number.png" alt="USB serial number"/><br/>
  <em>Image 2: USB serial number</em>
</p>

Based on the folder name, it is match the serial format `7095411056659025437&0`.

**Q2: Tracking USB device activity is essential for building an incident timeline, providing a starting point for your analysis. When was the last recorded time the USB was inserted into the system?**

Go to the folder in the source code above, I found the last recorded time is `2024-10-04 13:48`
```python
RegUtil.print_keyvalue(6, 'Last Insert:   ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066\\(Default)', True)))
```
<p align="center">
  <img src="./Assets/Image 3 - USB last insert time.png" alt="USB last insert time"/><br/>
  <em>Image 3: USB last insert time</em>
</p>

**Q3: Identifying the full path of the executable provides crucial evidence for tracing the attack's origin and understanding how the malware was deployed. What is the full path of the executable that was run after the PowerShell commands disabled Windows Defender protections?**

To know the full path of malicious, I need to view log. And according to [FS_Misc_Eventlog · ufrisk/MemProcFS Wiki · GitHub](https://github.com/ufrisk/MemProcFS/wiki/FS_Misc_Eventlog), I know the log is in the path `misc/eventlogs`.
<p align="center">
  <img src="./Assets/Image 4 - Event logs.png" alt="Event logs"/><br/>
  <em>Image 4: Event logs</em>
</p>

However, I cannot see the content of these logs, so I use third party tool EvtxECmd in "Log Analysis" category to parse these logs.
<p align="center">
  <img src="./Assets/Image 5 - Parsing logs.png" alt="Parsing logs"/><br/>
  <em>Image 5: Parsing logs</em>
</p>

To find which malicious was executed, I need to know when the attacker turn off Windows Defender protections. So I filter with powershell command first and found this command at about `13:49:48`.
<p align="center">
  <img src="./Assets/Image 6 - Attacker turn off windows defender.png" alt="Attacker turn off windows defender"/><br/>
  <em>Image 6: Attacker turn off windows defender</em>
</p>

Then I filter with sysmon eventID 1 - process creation after timestamp `13:49:48` to find the malicious process. Then right after that, at about `13:49:53`, attacker run a processes `E:\hidden\Trusted Installer.exe`. 
<p align="center">
  <img src="./Assets/Image 7 - Malicious process.png" alt="Malicious process"/><br/>
  <em>Image 7: Malicious process</em>
</p>

But I need to verify this is a malicious process, so I use MD5 hash `BC76BD7B332AA8F6AEDBB8E11B7BA9B6` from log line 626 above in VirusTotal.
<p align="center">
  <img src="./Assets/Image 8 - Verify malicious process.png" alt="Verify malicious process"/><br/>
  <em>Image 8: Verify malicious process</em>
</p>

**Q4: Identifying the bot malware’s C&C infrastructure is key for detecting IOCs. According to threat intelligence reports, what URL does the bot use to download its C&C file?**

To know the URL that the bot use to download C&C file, go to Relation category and I found 5 malicious URL. But only `http://anam0rph.su/in.php` match the format.
<p align="center">
  <img src="./Assets/Image 9 - Malicious URLs.png" alt="Malicious URLs"/><br/>
  <em>Image 9: Malicious URLs</em>
</p>

**Q5: Understanding the IOCs for files dropped by malware is essential for gaining insights into the various stages of the malware and its execution flow. What is the MD5 hash of the dropped .exe file?**

The `Trusted Installer.exe` also execute `Sahofivizu.exe` file. Still in the same line `632`, I can have the MD5 hash is `7FE00CC4EA8429629AC0AC610DB51993`.
<p align="center">
  <img src="./Assets/Image 10.1 - Dropped malicious file.png" alt="Dropped malicious file"/><br/>
  <img src="./Assets/Image 10.2 - Malicious hash.png" alt="Malicious hash"/><br/>
  <em>Image 10: Malicious file</em>
</p>

**Q6: Having the full file paths allows for a more complete cleanup, ensuring that all malicious components are identified and removed from the impacted locations. What is the full path of the first DLL dropped by the malware sample?**

Beside the dropped malicious file, malware `Trusted Installer.exe` also create some DLL files.
<p align="center">
  <img src="./Assets/Image 11 - Dropped DLL files.png" alt="Dropped DLL files"/><br/>
  <em>Image 11: Dropped DLL files</em>
</p>

And full path of the first DLL dropped by the malware is `C:\Users\Tomy\AppData\Local\Temp\Gozekeneka.dll`.

**Q7: Connecting malware to APT groups is crucial for uncovering an attack's broader strategy, motivations, and long-term goals. Based on IOCs and threat intelligence reports, which APT group reactivated this malware for use in its campaigns?**

From the image 8 - Verify malicious process above, the popular threat label is `trojan.gamarue/andromeda`. So I search for which is APT of its, and the correct answer is `Turla`.
<p align="center">
  <img src="./Assets/Image 12 - APT group of malicious.png" alt="APT group of malicious"/><br/>
  <em>Image 12: APT group of malicious</em>
</p>