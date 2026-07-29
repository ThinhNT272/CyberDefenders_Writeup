# Scenario & Objective

During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation. 

As part of the investigation, You are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

- **Category**: Network Forensics
- **Tools**: Wireshark, Scamalytics

## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

The PCAP file contains 33.279 packets from `07:45:15` to `08:26:30` in `2024-06-30`. The file contains multiple IP addresses and have SHA256 value `504b4a8cf895bf44f2dc3cdef3e0e5952e2d89913cd3525258dab40a7648e79c`.

At first, from the packet no 1, I know the internal server is `172.31.25.119`.
<p align="center">
  <img src="./Assets/Image 1 - Server connect SSH.png" alt="Server connect SSH" /> <br />
  <em>Image 1: Server connect SSH</em>
</p>

Then follow the scenario that the attacker upload webshells into the system, so I filter with IP of internal server and http POST method. Then I found 2 suspicious IP address `197.32.146.131` and `23.158.56.196`. So I need to verify the actual attacker IP address. 

First, I filter with IP `197.32.146.131` but it seems like nothing special. Then I filter with IP `23.158.56.196`. At first, according to scamalytics, this IP is flagged as high risk.
<p align="center">
  <img src="./Assets/Image 2 - Risk IP addr.png" alt="Risk IP addr" /> <br />
  <em>Image 2: Risk IP addr</em>
</p>

Moreover, from `07:57` to `08:01`, the suspicious IP also try to brute force into the system but it did not work.  
<p align="center">
  <img src="./Assets/Image 3 - Attacker try to brute force attack.png" alt="Attacker try to brute force attack" /> <br />
  <em>Image 3: Attacker try to brute force attack</em>
</p>

After that at `08:02`, attacker created and accessed the system using `c91oyemw` account.
<p align="center">
  <img src="./Assets/Image 4 - Attacker accessed credentials.png" alt="Attacker accessed credentials" /> <br />
  <em>Image 4: Attacker accessed credentials</em>
</p>

Then he upload a `pluginUpload.html` file that contains the file `NSt8bHTg.zip`. This file is designed to establish remote command execution on the compromised server.
<p align="center">
  <img src="./Assets/Image 5 - Malicious file.png" alt="Malicious file" /> <br />
  <em>Image 5: Malicious file</em>
</p>

Then from `08:03` to `08:19`, attack use some command as below.
```remote_cmd
ls --> ...

whoami --> root

pwd --> /opt/teamcity/bin

// raw: ls+%2Fopt%2Fteamcity
ls /opt/teamcity

// raw: ls+%2Fhome
ls /home

// raw: ls+~%2F
ls ~/

// raw: cd+%2Froot
cd /root

pwd --> /opt/teamcity/bin

ls /tmp --> ...

cat /tmp/Creds.txt --> username:a1l4m,password:mohamedsalah\n

bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'

cat /tmp/Creds.txt --> username:a1l4m,password:youarecompromised\n

docker run --rm -it --privileged ubuntu

docker run --rm -it -v /:/host ubuntu chroot /host

docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu

ls --> ...

whoami --> root
```

Then I want to know how the attacker can accessed and uploaded into the system because brute-force phase did not work. After that, the attacker changes tactics. He send GET request to `/hax?jsp=/app/rest/server;.jsp`, which is a non-standard path and ce be used to exploit the flaw in URL routing.

Then I filter with the internal server, I found that the system use `Teamcity - 2023.11.3` version. Then I research CVE of Teamcity version 2023.11.3  that exploit the flaw in URL. So I found the `CVE-2024-27198`. This has exactly the same semicolon with the path in the image 4. 
<p align="center">
  <img src="./Assets/Image 6.1 - CVE overview.png" alt="CVE overview" /> <br />
  <img src="./Assets/Image 6.2 - CVE IoC.png" alt="CVE IoC " /> <br />
  <em>Image 6: CVE information</em>
</p>


# Answer the Questions

**Q1: Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?**

It is `23.158.56.196`.

**Q2: To identify potential vulnerability exploitation, what version of our web server service is running?**

It is `2023.11.3`.

**Q3: After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?**

**Q4: The attacker exploited the vulnerability to create a user account. What credentials did he set up?**

It is `c91oyemw:CL5vzdwLuK`.

**Q5: The attacker uploaded a webshell to ensure his access to the system. What is the name of the file that the attacker uploaded?**

It is `NSt8bHTg.zip`.

**Q6: When did the attacker execute their first command via the web shell?**

It is `2024-06-30 08:03`.

**Q7: The attacker tampered with a text file that contained the credentials of the admin user of the webserver. What new username and password did the attacker write in the file?**

It is `a1l4m:youarecompromised`.

**Q8: What is the MITRE Technique ID for the attacker's action in the previous question (Q7) when tampering with the text file?**

Based on the activities of question 7, the relevant MITRE ATT&CK sub-technique under the Data Manipulation category is `T1565.001 - Data Manipulation: Stored Data`.

This sub-technique involves an attacker modifying stored data, such as files containing credentials, to achieve their objectives. In the context of the attacker modifying the `/tmp/creds.txt` file to insert new credentials, the action directly aligns with `T1565.001`, as it manipulates stored data to grant unauthorized access and maintain persistence.

**Q9: The attacker tried to escape from the container but he didn’t succeed, What is the command that he used for that?**

Attacker use command `docker run --rm -it -v /:/host ubuntu chroot /host`.
