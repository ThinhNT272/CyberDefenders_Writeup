# Scenario & Objective

Endpoint Detection and Response (EDR) system alert a malware Amadey Trojan Stealer on Windows machine. My job is to analyze the presented memory dump and create a detailed report for actions taken by the malware. 

I will use Volatility3 - one of the most widely used framework for extracting digital artifacts from RAM - to analyze file `Windows 7 x64-Snapshot4.vmem`. 

SHA256 hash (Windows 7 x64-Snapshot4.vmem): 51bca9647e7f17da9391a23da27e8248f65e460f9b74d65e0b2ef1e06e1a7c3c

- **Category**: Endpoint Forensics
- **Tools**: Volatility 3
## Overview

The file belong to user `0xSh3rl0ck` in host `Win7 SP1`, IP address is `192.168.195.136`. This file was created at `21:50:07` on `2023-08-09`.

At about `21:33`, the malicious file `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5lssass.exe` was executed with PID `2748` by anonymous user `0XSH3R~1`. The malware connect to C2 server `41.75.84.12:80` through port `49168`. It try to install `cred64.dll` and `clip64.dll` into workstation.

This malicious file was also located `\Windows\System32\Tasks\lssass.exe` to make sure persistent connection. 
# Answer the Questions

First, I want to know all the plugins that available wil `window.vmem` file.
```all-wins-plugins
	windows.bigpools.BigPools
            List big page pools.
    windows.callbacks.Callbacks
            Lists kernel callbacks and notification routines.
    windows.cmdline.CmdLine
            Lists process command line arguments.
    windows.crashinfo.Crashinfo
            Lists the information from a Windows crash dump.
    windows.devicetree.DeviceTree
            Listing tree based on drivers and attached devices in a particular
            windows memory image.
    windows.dlllist.DllList
            Lists the loaded modules in a particular windows memory image.
    windows.driverirp.DriverIrp
            List IRPs for drivers in a particular windows memory image.
    windows.drivermodule.DriverModule
            Determines if any loaded drivers were hidden by a rootkit
    windows.driverscan.DriverScan
            Scans for drivers present in a particular windows memory image.
    windows.dumpfiles.DumpFiles
            Dumps cached file contents from Windows memory samples.
    windows.envars.Envars
            Display process environment variables
    windows.filescan.FileScan
            Scans for file objects present in a particular windows memory image.
    windows.getservicesids.GetServiceSIDs
            Lists process token sids.
    windows.getsids.GetSIDs
            Print the SIDs owning each process
    windows.handles.Handles
            Lists process open handles.
    windows.info.Info 
		    Show OS & kernel details of the memory sample being analyzed.
    windows.joblinks.JobLinks
            Print process job link information
    windows.ldrmodules.LdrModules
            Lists the loaded modules in a particular windows memory image.
    windows.malfind.Malfind
            Lists process memory ranges that potentially contain injected code.
    windows.mbrscan.MBRScan
            Scans for and parses potential Master Boot Records (MBRs)
    windows.memmap.Memmap
            Prints the memory map
    windows.modscan.ModScan
            Scans for modules present in a particular windows memory image.
    windows.modules.Modules
            Lists the loaded kernel modules.
    windows.mutantscan.MutantScan
            Scans for mutexes present in a particular windows memory image.
    windows.netscan.NetScan
            Scans for network objects present in a particular windows memory image.
    windows.netstat.NetStat
            Traverses network tracking structures present in a particular windows 
            memory image.
    windows.poolscanner.PoolScanner
            A generic pool scanner plugin.
    windows.privileges.Privs
            Lists process token privileges
    windows.pslist.PsList
            Lists the processes present in a particular windows memory image.
    windows.psscan.PsScan
            Scans for processes present in a particular windows memory image.
    windows.pstree.PsTree
            Plugin for listing processes in a tree based on their parent process 
            ID.
    windows.registry.certificates.Certificates
            Lists the certificates in the registry's Certificate Store.
    windows.registry.hivelist.HiveList
            Lists the registry hives present in a particular memory image.
    windows.registry.hivescan.HiveScan
            Scans for registry hives present in a particular windows memory image.
    windows.registry.printkey.PrintKey
            Lists the registry keys under a hive or specific key value.
    windows.registry.userassist.UserAssist
            Print userassist registry keys and information.
    windows.sessions.Sessions
            lists Processes with Session information extracted from Environmental
            Variables
    windows.skeleton_key_check.Skeleton_Key_Check
            Looks for signs of Skeleton Key malware
    windows.ssdt.SSDT   
		    Lists the system call table.
    windows.statistics.Statistics
            Lists statistics about the memory space.
    windows.strings.Strings
            Reads output from the strings command and indicates which process(es)
            each string belongs to.
    windows.symlinkscan.SymlinkScan
            Scans for links present in a particular windows memory image.
    windows.vadinfo.VadInfo
            Lists process memory ranges.
    windows.vadwalk.VadWalk
            Walk the VAD tree.
    windows.verinfo.VerInfo
            Lists version information from PE files.
    windows.virtmap.VirtMap
            Lists virtual mapped sections.
```
I want to know more about the host of this ".vmem" file, I use `windows.info` plugin.
```OS-info
Kernel Base	0xf80002a55000
DTB	0x187000
Symbols	file:///home/ubuntu/Desktop/Start%20here/Tools/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdDebuggerDataBlock	0xf80002c460a0
NTBuildLab	7601.17514.amd64fre.win7sp1_rtm.
CSDVersion	1
KdVersionBlock	0xf80002c46068
Major/Minor	15.7601
MachineType	34404
KeNumberProcessors	1
SystemTime	2023-08-09 21:50:07
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	6
NtMinorVersion	1
PE MajorOperatingSystemVersion	6
PE MinorOperatingSystemVersion	1
PE Machine	34404
PE TimeDateStamp	Sat Nov 20 09:30:02 2010
```
To know more about the hostname or user, I will see registry of file. So I collect some information below :

- **OS**: Windows 7 Service Pack 1
- **Architecture**: 64bit 
- **User**: 0xSh3rl0ck
- **File memory was created at**: `21:50:07` of `2023-08-09`. 

**Q1: In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?**

From the list above, I know I need to use this plugin `windows.pstree.PsTree`. So, I found the suspicious executable file called `rundll32.exe`. And its parent is `lssass.exe` with PID `2748`. This process ran at `21:33` on `2023-08-09`.
<p align="center">
  <img src="Image 1 - Parent process of malware.webp" alt="Parent process of malware" /> <br />
  <em>Image 1: Parent process of malware</em>
</p>

**Q2: Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?**

Usually the command line to run the file will contain the directory of that file. So I check with plugin `windows.cmdline`.
<p align="center">
  <img src="Image 2 - Malware directory.webp" alt="Malware directory" /> <br />
  <em>Image 2: Malware directory</em>
</p>
 The answer will be `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe` because `lssass.exe` is a parent process of `rundll32.exe`.

And from that, I know the malicious user is `0XSH3R~1`.

**Q3: Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?**

The malware will open port back to the C2 server so I check the network with plugin `windows.netscan`. So I foudn that the `lssass.exe` connect from `192.168.195.136:49168` (victim IP) to `41.75.84.12:80` (C2 server).
<p align="center">
  <img src="Image 3 - C2 server.webp" alt="C2 server" /> <br />
  <em>Image 3: C2 server</em>
</p>

**Q4: Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?**

To know how many distinct files is the malicious process trying to bring onto the compromised host, I will dump all activity of process `lssass.exe` with command `python3 vol.py -f /home/ubuntu/Desktop/Start\ here/Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.memmap --dump --pid 2748`. And it will create a `pid.2748.pmd` file.

Then I know the C2 server connects to this process through port `80`, represent they use HTTP to control the malware. Then I can filter the `pid.2748.pmd` file with `GET` method.
<p align="center">
  <img src="Image 4 - Files added to workstation.webp" alt="Files added to workstation" /> <br />
  <em>Image 4: Files added to workstation</em>
</p>
Malware bring `2` files (`cred64.dll` and `clip64.dll`) onto workstation.

**Q5: Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?**

To see full path of file, I filter `python3 vol.py -f /home/ubuntu/Desktop/Start\ here/Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.filescan > filescan.txt`. Then use grep command to find specific files.
<p align="center">
  <img src="Image 5 - Full path of downloaded file.webp" alt="Full path of downloaded file" /> <br />
  <em>Image 5: Full path of downloaded file</em>
</p>
So, full path of `clip64.dll` is `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`.

**Q6: Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?**

From image 2 above, I can see that `rundll.exe` is  the process that execute the `clip64.dll`.

**Q7: Understanding the full range of Amadey's persistence mechanisms can help in an effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?**

To know where the malware `lssass.exe` loacte for ensuring the persistence mechanisms, I use the `filescan.txt` from the previous step.
<p align="center">
  <img src="Image 6 - Malware location.webp" alt="Malware location" /> <br />
  <em>Image 6: Malware location</em>
</p>
I see malware located in 2 folder. But the `Temp` folder represent the malware is running. And the `\Windows\System32\Tasks\lssass.exe` shows the malware was in deep of the OS, indicates the persistence mechanisms.