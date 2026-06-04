# Scenario & Objective

An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicates potential unauthorized access and movement across the network. As a SOC Analyst, your task is to investigate the provided PCAP file to trace the attacker’s activities. Identify their entry point, the machines targeted, the extent of the breach, and any critical indicators that reveal their tactics and objectives within the compromised environment.

- **Category**: Network Forensics
- **Tools**: Wireshark

PsExex is lightweight, command-line utility from the Microsoft Sysinternals suite that allows administrators to execute processes on remote Windows systems. It use SMB protocol to establish communication channels with remote systems. It also support various authentication methods, including using a username and password, or authentication via NTLM or Kerberos.

# Overview

During a security incident, the network IDS detected suspicious lateral movement within the network. An attacker, operating from IP **10.0.0.130**, used the compromised credentials of the user account **ssales** to access other machines. 

The attacker first pivoted to **SALES-PC** (**10.0.0.133**) by connecting to the hidden `ADMIN$` share and installing a remote service named **PSEXESVC.exe**. They executed this service via the DCERPC protocol and used the `IPC$` network share to establish a communication channel. After successfully compromising SALES-PC, the attacker continued lateral movement by targeting a second machine, **MARKETING-PC** (**10.0.0.131**).

# Analysis

First, I check all IPv4 addresses and all protocols exist in the PCAP file. 
<p align="center">
  <img src="./Assets/Image 1 - All Ipv4 addresses.webp" alt="All Ipv4 addresses" /> <br />
  <em>Image 1: All Ipv4 addresses</em>
</p>

<p align="center">
  <img src="./Assets/Image 2 - All protocols.webp" alt="All protocols" /> <br />
  <em>Image 2: All protocols</em>
</p>

After searching, I found the packet no 132. The `10.0.0.130:49696` connected to `10.0.0.133:445` via SMB2 protocol under account `ssales` in host `HR-PC`. Then, `10.0.0.130` accessed to `IPC$` and `ADMIN$` folder, both requests are success because I found a `NT Status: STUSTUS_SUCCESS` in both reponse packets. 
<p align="center">
  <img src="./Assets/Image 3 - Initial access.webp" alt="Initial access" /> <br />
  <em>Image 3: Initial access</em>
</p>

> [!note]
> The `IPC$` (Inter-Process Communication) share or also known as a null session connection is a hidden, virtual administrative share in Windows used for communication between network programs and remote administration. It does not map to a physical folder on the hard drive but acts as a conduit for to allow processes to interact across machine.
> 
> The `ADMIN$` folder is a hidden, default administrative share in Windows that points directly to the system root directory (typically `C:\Windows`). Used primarily by network administrators, it enables remote management, allowing them to access system files, manage configurations, and deploy software over a network without physical access to the machine

Then in the packet 140, `10.0.0.130` request to open the `ADMIN$` folder. This is an exploratory step. `10.0.0.130`, attacker want to make sure the `ADMIN$` folder exist. 
<p align="center">
  <img src="./Assets/Image 4 - Exploratory phase.webp" alt="Exploratory phase" /> <br />
  <em>Image 4: Exploratory phase</em>
</p>

Then, `10.0.0.130` create `PSEXESVC.exe` file in `ADMIN$` folder. 
<p align="center">
  <img src="./Assets/Image 5 - Upload PSEXESVC.exe.webp" alt="Upload PSEXESVC.exe" /> <br />
  <em>Image 5: Upload PSEXESVC.exe</em>
</p>

Then, to follow this traffic, I filtered with `ip.addr == 10.0.0.130`. After create a file, `10.0.0.130` want to write data into that file through `write request`.
<p align="center">
  <img src="./Assets/Image 6 - Another file.webp" alt="Another file" /> <br />
  <em>Image 6: Another file</em>
</p>

After attacker closed the `PSEXESVC.exe` file, I found the DCERPC protocol from attacker.
<p align="center">
  <img src="./Assets/Image 7 - Run the PSEXECSVC.exe.webp" alt="Run the PSEXECSVC.exe" /> <br />
  <em>Image 7: Run the PSEXECSVC.exe</em>
</p>

> [!note]
> DCERPC is a networking framework that allows a computer program to execute procedures on a remote server as if they were local

It proved that the attacker ran the `PSEXECSVC.exe` program by using DCE/RPC protocol.

Then, attacker also created and writed the file `PSEXEC-HR-PC-1C6C5D14.key` in the `ADMIN$` folder. As I understand, the attacker want `PSEXEC.exe` use this key so that the he and system can communicate to each other.
<p align="center">
  <img src="./Assets/Image 8 - Create file.key.webp" alt="Create file.key" /> <br />
  <em>Image 8: Create file.key</em>
</p>

Then he open the `PSEXESVC` pipe name in `IPC$`. This pipe name had already appeared in the `IPC$` because attacker run the `PSEXESVC.exe` in the previous step. 

# Answer the Questions

**Q1: To effectively trace the attacker's activities within our network, can you identify the IP address of the machine from which the attacker initially gained access?**

Attacker IP is `10.0.0.130`.

**Q2: To fully understand the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?**

 First pivoted of the attacker is `10.0.0.133`. To know the hostname of this machine, I cameback to the `session setup` process and I found the the information in the packet 131, `Target Name: SALES-PC`.

**Q3: Knowing the username of the account the attacker used for authentication will give us insights into the extent of the breach. What is the username utilized by the attacker for authentication?**

Attacker use `10.0.0.130`, so the answer is `ssales`.

**Q4: After figuring out how the attacker moved within our network, we need to know what they did on the target machine. What's the name of the service executable the attacker set up on the target?**

As I analysed above, attacker set up `PSEXESVC.exe`.

**Q5: We need to know how the attacker installed the service on the compromised machine to understand the attacker's lateral movement tactics. This can help identify other affected systems. Which network share was used by PsExec to install the service on the target machine?**

On hidden `ADMIN$` folder.

**Q6: We must identify the network share used to communicate between the two machines. Which network share did PsExec use for communication?**

PsExec use `IPC$` network for communication.

**Q7: Now that we have a clearer picture of the attacker's activities on the compromised machine, it's important to identify any further lateral movement. What is the hostname of the second machine the attacker targeted to pivot within our network?**

The second target is `10.0.0.131`, so the hostname of second machine is `MARKETTING-PC`.