# Scenario & Objective

An automated alert has detected unusual XML data being processed by the server, which suggests a potential XXE (XML External Entity) Injection attack. This raises concerns about the integrity of the company's customer data and internal systems, prompting an immediate investigation.

Analyze the provided PCAP file using the network analysis tools available to you. Your goal is to identify how the attacker gained access and what actions they took.

- **Category**: Network Forensics
- **Tools**: Wireshark

## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

The PCAP file contains 88577 packets from `11:47:05` to `12:29:12` in `2024-05-31`. The file contains multiple IP addresses and have SHA256 value `a3e15bfe5432c7588f5d073e01fc25f742dbeecb67f68bcbab2073b5158da00c`.

In this PCAP file, there is only 2 IP addresses, which mean one of them is attacker and the rest is the server.
<p align="center">
  <img src="./Assets/Image 1 - All IP addresses.png" alt="All IP addresses" /> <br />
  <em>Image 1: All IP addresses</em>
</p>

At about `11:47`, attacker `210.106.114.183` using nmap NSE to scan network assets of the system. Moreover, I found the server run `Apache/2.4.58 (Ubuntu)`.
<p align="center">
  <img src="./Assets/Image 2.1 - Nmap scan.png" alt="Nmap scan" /> <br />
  <img src="./Assets/Image 2.2 - Attacker scan.png" alt="Attacker scan" /> <br />
  <em>Image 2: Scan phase</em>
</p>

Then from `11:50` to `11:51`, attacker use `gobuster` to scan hidden assets.
<p align="center">
  <img src="./Assets/Image 3 - Attacker using gobuster.png" alt="Attacker using gobuster" /> <br />
  <em>Image 3: Attacker using gobuster</em>
</p>

Moreover, at about `11:55`, attacker upload a file `TheGreatGatsby.xml` file, which is used for access resources via URL. And it got information as below.
<p align="center">
  <img src="./Assets/Image 4 - Malicious file.png" alt="Malicious file" /> <br />
  <em>Image 4: Malicious file</em>
</p>

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
```

At about `12:01`, attack upload a second XML file `1984.xml`. And it got the information as below.
<p align="center">
  <img src="./Assets/Image 5 - Scecond malicious file.png" alt="Scecond malicious file" /> <br />
  <em>Image 5: Scecond malicious file</em>
</p>

At about `12:03`, he upload the third file `ToKillaMockingbird.xml`
<p align="center">
  <img src="./Assets/Image 6 - Third malicious file.png" alt="Third malicious file" /> <br />
  <em>Image 6: Third malicious file</em>
</p>

```
$db_host = 'localhost';
$db_name = 'pageturner';
$db_user = 'webuser';
$db_pass = 'Winter2024';
```

At `12:08`, after getting those information, attacker access to the SQL service using credentials above.
<p align="center">
  <img src="./Assets/Image 7 - Access SQL server.png" alt="Access SQL server" /> <br />
  <em>Image 7: Access SQL server</em>
</p>

Then at `12:15`, attacker upload the four XML file `PrideandPrejudice.xml` that contain `booking.php` script.
<p align="center">
  <img src="./Assets/Image 8 - Four malicious file.png" alt="Four malicious file" /> <br />
  <em>Image 8: Four malicious file</em>
</p>

Then from `12:19` to `12:29`, attack peform some command in the system via `booking.php` script.
<p align="center">
  <img src="./Assets/Image 9 - Attacker run command.png" alt="Attacker run command"/><br />
  <em>Image 9: Attacker run command</em>
</p>

# Answer the Questions

**Q1: Identifying the open ports discovered by an attacker helps us understand which services are exposed and potentially vulnerable. Can you identify the highest-numbered port that is open on the victim's web server?**

To identify which port is open on the server, I filter with SYN packet.
<p align="center">
  <img src="./Assets/Image 10 - Highest port.png" alt="Highest port"/><br />
  <em>Image 10: Highest port</em>
</p>

So the correct answer is `3306`.

**Q2: By identifying the vulnerable PHP script, security teams can directly address and mitigate the vulnerability. What's the complete URI of the PHP script vulnerable to XXE Injection?**

It is `/review/upload.php`.

**Q3: To construct the attack timeline and determine the initial point of compromise. What's the name of the first malicious XML file uploaded by the attacker?**

It is `TheGreatGatsby.xml`.

**Q4: Understanding which sensitive files were accessed helps evaluate the breach's potential impact. What's the name of the web app configuration file the attacker read?**

It is `config.php`.

**Q5: To assess the scope of the breach, what is the password for the compromised database user?**

It is `Winter2024`.

**Q6: Following the database user compromise. What is the timestamp of the attacker's initial connection to the MySQL server using the compromised credentials after the exposure?**

It is `2024-05-31 12:08`.

**Q7: To eliminate the threat and prevent further unauthorized access, can you identify the name of the web shell that the attacker uploaded for remote code execution and persistence?**

It is `booking.php`.