# Scenario & Objective

There is an alert about a suspicious file on web server. The IT team decided to capture network traffic into PCAP file for review. 

My job is analyze the provided PCAP file to uncover how the file appeared and determine the extent of unauthorized activity.

- **Category**: Network Forensics
- **Tools**: Wireshark

## Overview

An external threat actor operating from IP `117.11.88.124`, geolocated to **Tianjin, China**, using a Linux machine with Firefox 115.0.

The attacker exploited a **file upload vulnerability** on the company's web server (`24.49.63.79`) by uploading a malicious PHP web shell (`image.jpg.php`) - bypassing file extension filters. The web shell established a reverse connection back to the attacker on port 8080 and was used to exfiltrate the server's `/etc/passwd` file.

During the time period captured in the PCAP file, the attack followed a sequential pattern: reconnaissance → upload attempts → successful shell upload → command execution → data exfiltration.

The attack targeted the company's **web server** (`24.49.63.79:80`). The upload functionality at `/reviews/uploads/` was the entry point. The malicious web shell was stored in the uploads directory on the server.

The attacker's objective was data exfiltration. After gaining remote code execution through the web shell, the attacker targeted `/etc/passwd` - a common first step in post-exploitation to enumerate system users, identify service accounts, and plan further privilege escalation or lateral movement.

# Answer the Questions

**Q1: Identifying the geographical origin of the attack facilitates the implementation of geo-blocking measures and the analysis of threat intelligence. From which city did the attack originate?**

To find geographical origin of the attacker, I need to filter IP address of an attacker in this PCAP file. Go to Statistics > IPv4 Statistics > All Addresses, I have a table that represent all IPv4 address in this PCAP file. 
<p align="center">
  <img src="./Assets/Image 1 - All IPv4 address.webp" alt="All IPv4 address" />
  <em>Image 1: All IPv4 addresses</em>
</p>

Luckily, it is only 2 IP, `24.49.63.79` and `117.11.88.124` So one of them is attacker and the other is web server. 

Then when I check the first traffic, I see that `117.11.88.124` sent a TCP SYN packet to the `24.49.63.79` through port 80, which represent for HTTP. So I know that `24.49.63.79` is web server and `117.11.88.124` is the attacker. 
<p align="center">
  <img src="./Assets/Image 2 - TCP SYN connect.webp" alt="TCP SYN connect" />
  <em>Image 2: TCP SYN connect</em>
</p>

Then I go to geolocation IP lookup web and have the result that IP `117.11.88.124` come from `Tianjin, China`.
<p align="center">
  <img src="./Assets/Image 3 - Geolocation of attacker.webp" alt="TCP SYN connect" />
  <em>Image 3: Geolocation of attacker</em>
</p>

**Q2: Knowing the attacker's User-Agent assists in creating robust filtering rules. What's the attacker's Full User-Agent?**

To see User-Agent of the attacker, select any HTTP traffic and open "Hypertext Transfer Protocol". 
<p align="center">
  <img src="./Assets/Image 4 - Attacker User-Agent.webp" alt="Attacker User-Agent" />
  <em>Image 4: Attacker User-Agent</em>
</p>

Based on the information above, I know that the attacker use Firefox browser in Linux to attack company webserver. The full User-Agent is `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0`.

**Q3: We need to determine if any vulnerabilities were exploited. What is the name of the malicious web shell that was successfully uploaded?**

I need to know which protocol that attacker use to upload malicious web shell into web server of company. So I go to Statistics > Protocol Hierarchy to see all protocol in this PCAP file. 
<p align="center">
  <img src="./Assets/Image 5 - All protocol.webp" alt="All protocol" />
  <em>Image 5: All protocol</em>
</p>

There is only HTTP protocol in Application layer that the attacker can use to send malicious web shell. And to upload anything, attacker have to use POST method. Based on this information, I can filter HTTP POST traffic in Wireshark `http.request.method == POST`.
<p align="center">
  <img src="./Assets/Image 6 - Name of the malicious web shell.webp" alt="Name of the malicious web shell" />
  <em>Image 6: Name of the malicious web shell</em>
</p>

When I check the packet number `53`, I see that the attacker sent a "image.php" malicious web shell, but it seems like not working because web server do not response any information. So attacker sent  `image.jpg.php` and now it worked. The packet number `267` show that the web server send back some information to the attacker.

**Q4: Identifying the directory where uploaded files are stored is crucial for locating the vulnerable page and removing any malicious files. Which directory is used by the website to store the uploaded files?**

Right click to the packet number `63` and select Follow > HTTP Stream to see more information.
<p align="center">
  <img src="./Assets/Image 7 - Malicious web shell.webp" alt="Malicious web shell" />
  <em>Image 7: Malicious web shell</em>
</p>

I can see that this is not automatic script. Which mean, attacker need to run the script by some how to open connect back to the attacker. So I can search for file name is "image.jpg.php".
<p align="center">
  <img src="./Assets/Image 8 - Upload folder.webp" alt="Upload folder" />
  <em>Image 8: Upload folder</em>
</p>

So, the malicious web shell is stored in `reviews/uploads` folder.

**Q5: Which port, opened on the attacker's machine, was targeted by the malicious web shell for establishing unauthorized outbound communication?**

Look at the "Image 7: Malicious web shell" above. So I know that the malicious web shell connect to the attacker machine through port `8080`.

**Q6: Recognizing the significance of compromised data helps prioritize incident response actions. Which file was the attacker attempting to exfiltrate?**

Based on packet number `267` that web server send back to the attacker, I know that the attacker want to steal `/etc/passwd` file.
<p align="center">
  <img src="./Assets/Image 9 - Attacker attempt to exfiltrate file.webp" alt="Attacker attempt to exfiltrate file" />
  <em>Image 9: Attacker attempt to exfiltrate file</em>
</p>