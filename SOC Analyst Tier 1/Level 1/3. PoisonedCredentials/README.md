# Scenario & Objective

Your organization's security team has detected a surge in suspicious network activity. There are concerns that LLMNR (Link-Local Multicast Name Resolution) and NB-NS (NetBIOS Name Service) poisoning attacks may be occurring within your network. These attacks are known for exploiting these protocols to intercept network traffic and potentially compromise user credentials. 

My task is to investigate the network logs and examine captured network traffic called "PoisonedCredentials.pcap". 

SHA256 hash (PoisonedCredentials.pcap): a0703e71eef0c44f18e580951d8d6439289ff0d2e8d7726a09048f39ae4e989a

- **Category**: Network Forensics
- **Tools**: Wireshark

First, I need to know what is LLMNR and NBT-NS poison attack? Basically, it is a man-in-the-middle (MitM) attack because of the UDP protocol that both LLMNR and NBT-NS use. And these protocol are not use any authentication techniques. So the attacker can intercept NetBIOS name resolution requests and reply with malicious responses. Then the victim will connect to the attacker instead of the real server. 
## Overview

At `20:32` on `2023-10-21` , attacker used the LLMNR poison technique to trick the victim `192.168.232.176` that he was `prinetr`.  At `20:33`, attacker compromised victim `ACCOUNTINGPC - 192.168.232.176` via SMB2 using username `janesmith` of domain `cybercactus.local` and `NTLM Response`.

`NTLM Response = 0312c0aeaedcc76acf103bcada22c2b901010000000000008030adcd5d04da01436528b5e6342a8c000000000200160043005900420045005200430041004300540055005300010018004100430043004f0055004e00540049004e0047005000430004002200630079006200650072006300610063007400750073002e006c006f00630061006c0003003c004100630063006f0075006e00740069006e006700500043002e00630079006200650072006300610063007400750073002e006c006f00630061006c0005002200630079006200650072006300610063007400750073002e006c006f00630061006c000700080021bcd0cd5d04da010000000000000000`

# Analysis

Firstly, I check for some information of the PCAP file. This file recorded network traffic from `20:26` to `20:33` in `2023-10-21`. It contais `269` packets with `8` diffirent IP addresses. The main type of network traffic is `SMB2` with `15.2%` of all packets.
<p align="center">
  <img src="Image 1 - All IPv4.webp" alt="All IPv4" /> <br />
  <em>Image 1: All IPv4</em>
</p>
<p align="center">
  <img src="Image 2 - Main type of protocol.webp" alt="Main type of protocol" /> <br />
  <em>Image 2: Main type of protocol</em>
</p>
I know the attacker use LLMNR and NB-NS poison attack, so I filtered with these traffic. Then, I found `192.168.232.162` requested for `fileshaare` instead of `fireshare` in both protoco. However the mistyped of the request, the host with IP address `192.168.232.215` still responsed in both protocols and pointed to it self as `fileshaare`.
<p align="center">
  <img src="Image 3 - LLMNR fileshaare.webp" alt="LLMNR fileshaare" /> <br />
  <em>Image 3: LLMNR fileshaare</em>
</p>
<p align="center">
  <img src="Image 4 - NB-NS fileshaare.webp" alt="NB-NS fileshaare" /> <br />
  <em>Image 4: NB-NS fileshaare</em>
</p>
Then when another host `192.168.232.176` requested for `printer`, `192.168.232.215` also response and said it is a printer. The same with another domain name `cybercactus`.
<p align="center">
  <img src="Image 5 - LLMNR printer.webp" alt="LLMNR printer" /> <br />
  <em>Image 5: LLMNR printer</em>
</p>
<p align="center">
  <img src="Image 6 - NB-NS cybercactus.webp" alt="NB-NS cybercactus" /> <br />
  <em>Image 6: NB-NS cybercactus</em>
</p>
`192.168.232.215` cannot be `fileshaare`, `prinetr` and `CYBERCACTUS` at the same time, so it must be the attacker. Here is some information of the attacker.

- **IPv4 address**: `192.168.232.215`
- **IPv6 address**: `fe80::c0a9:714f:8ea7:3313`
- **MAC address**: `00:0c:29:44:ca:ef`

Now I know the attacker, then I want to know what did he do in the network. So I filtered with his IP address. 

Then, I found that at `20:33` attacker connected to `192.168.232.176` via SMB2, using account `janesmith` on `WORKSTATION` host of domain `cybercactus.local`. We also know the NTLM `server challenge: c8eb5e4b7c037617` and `NTLM Response 0312c0aeaedcc76acf103bcada22c2b901010000000000008030adcd5d04da01436528b5e6342a8c000000000200160043005900420045005200430041004300540055005300010018004100430043004f0055004e00540049004e0047005000430004002200630079006200650072006300610063007400750073002e006c006f00630061006c0003003c004100630063006f0075006e00740069006e006700500043002e00630079006200650072006300610063007400750073002e006c006f00630061006c0005002200630079006200650072006300610063007400750073002e006c006f00630061006c000700080021bcd0cd5d04da010000000000000000`.
<p align="center">
  <img src="Image 7 - NTLM Challenge.webp" alt="NTLM Challenge" /> <br />
  <em>Image 7: NTLM Challenge</em>
</p>
<p align="center">
  <img src="Image 8 - NTLM Response.webp" alt="NTLM Response" /> <br />
  <em>Image 8: NTLM Response</em>
</p>
<p align="center">
  <img src="Image 9 - Attacker connect via SMB2.webp" alt="Attacker connect via SMB2" /> <br />
  <em>Image 9: Attacker connect via SMB2</em>
</p>
And in the packet 241, I found some information of victime machine.

- IPv4 address: `192.168.232.176`
- MAC address: `00:0c:29:9c:01:34`
- NetBIOS name: `ACCOUNTINGPC`
<p align="center">
  <img src="Image 10 - Victim NetBIOS name.webp" alt="Victim NetBIOS name" /> <br />
  <em>Image 10: Victim NetBIOS name</em>
</p>
And the packets from 251 to 258 is the data that attacker got. I cannot see the data because of the encryption.
<p align="center">
  <img src="Image 11 - Data encrypted.webp" alt="Data encrypted" /> <br />
  <em>Image 11: Data encrypted</em>
</p>
Based on the information that I analysis above, I can answer the questions now
# Answer the Questions

**Q1: In the context of the incident described in the scenario, the attacker initiated their actions by taking advantage of benign network traffic from legitimate machines. Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?**

It is `filshaare`.

**Q2: We are investigating a network security incident. To conduct a thorough investigation, We need to determine the IP address of the rogue machine. What is the IP address of the machine acting as the rogue entity?**

The rogue machine is `192.168.232.215`.

**Q3: As part of our investigation, identifying all affected machines is essential. What is the IP address of the second machine that received poisoned responses from the rogue machine?**

It is `192.168.232.176`.

**Q4: We suspect that user accounts may have been compromised. To assess this, we must determine the username associated with the compromised account. What is the username of the account that the attacker compromised?**

It is `janesmith`.

**Q5: As part of our investigation, we aim to understand the extent of the attacker's activities. What is the hostname of the machine that the attacker accessed via SMB?**

It is `AccountingPC`.

# Question

Con 215 lấy `NTLMv2 Response` từ đâu ra? Và tại sao lại là host 215 negotiate request tới client 176?
![[README-1778780254379.webp]]