# Scenario & Objective

You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.  

As the lead analyst in this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.

- **Category**: Network Forensics
- **Tools**: Wireshark, IP Location, CyberChef, Code Beautify

## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

I was provided a pcap file that contain `88.862` packets from `18:39:21` to `19:26:33` in `2024-03-15`.  The file has SHA256 value `cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647`.

Moreover, the file contains 5 IP addresses with the main protocol is HTTP.
<p align="center">
  <img src="./Assets/Image 1.1 - All IP addresses.webp" alt="All IP addresses" /> <br />
  <img src="./Assets/Image 1.2 - Main protocol.webp" alt="Main protocol" /> <br />
  <em>Image 1: Overall information in the pcap file</em>
</p>

At first, the IP `170.40.150.126` connect to `73.124.22.98`. From some GET packet by `170.40.150.126`, I know the `73.124.22.98` is a web server of BookWorld with domain `bookworldstore.com`. But it seems nothing special with this IP because he just querry some normal books.

Then at about `19:01:36`, the host `111.224.250.131` connect to web server. This is an attacker because he has many SQL injection querries in the `search.php`.

```
# book and 1=1; -- -
book%20and%201=1;%20--%20-

# test’ OR 1=1; --
test%E2%80%99%20OR%201=1;%20--

# /' or 1=1; -- -
/%27%20or%201=1;%20--%20-
```

Moreoever, I know the attacker come from `Shijiazhuang, China`.
<p align="center">
  <img src="./Assets/Image 2 - Geograpohical of attacker.webp" alt="Geograpohical of attacker" /> <br />
  <em>Image 2: Geograpohical of attacker</em>
</p>

Those querries above don't work, so at `19:07:34` he used `sqlmap` tool to automates the detection and exploitation of SQL injection vulnerabilities.
<p align="center">
  <img src="./Assets/Image 3 - Attacker use sqlmap tool.webp" alt="Attacker use sqlmap tool" /> <br />
  <em>Image 3: Attacker use sqlmap tool</em>
</p>
He find much information. At about `19:08:57`, packet 1548, attacker use querry like this. This is URL encode with many strings begin with `0x`, this represent the hex string. So I decode all the querry.

```
# Original
search=book%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178766271%2CJSON_ARRAYAGG%28CONCAT_WS%280x7a76676a636b%2Ctable_name%29%29%2C0x7176706a71%29%20FROM%20INFORMATION_SCHEMA.TABLES%20WHERE%20table_schema%20IN%20%280x626f6f6b776f726c645f6462%29--%20-

# URL decode & Hex to string
search=book' UNION ALL SELECT NULL,CONCAT(qxvbq,JSON_ARRAYAGG(CONCAT_WS(zvgjck,table_name)),qvpjq) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (bookworld_db)-- -
```

Basically, this command querry the table in the schema `bookworld_db`. There are 3 tables `admin`, `book` and `customers`.
<p align="center">
  <img src="./Assets/Image 4 - Attacket get table from db.webp" alt="Attacket get table from db" /> <br />
  <em>Image 4: Attacket get table from db</em>
</p>

At about `19:09`, he querry for table `admin` in the packet 1589 & 1591 and get this.

```
# URL decode & hex to string
search=book' UNION ALL SELECT NULL,CONCAT(qxvbq,JSON_ARRAYAGG(CONCAT_WS(zvgjck,id,password,username)),qvpjq) FROM bookworld_db.`admin`-- -

# Result
<p>qxvbq["1zvgjckadmin123!zvgjckadmin"]qvpjq</p><form action="search.php" method="get">\n
```

If remove `zvgjck` from the answer, I just get the id, password and username as `1`, `admin123!`, `admin` respectively.

Then in that packet 1622 & 1624, he got some customer information through table `customer`.

```
# URL decode & hex to string
search=book' UNION ALL SELECT NULL,CONCAT(qxvbq,JSON_ARRAYAGG(CONCAT_WS(zvgjck,address,email,first_name,id,last_name,phone)),qvpjq) FROM bookworld_db.customers-- -

# Result
<p>qxvbq["123 Maple Streetzvgjckjohn.doe1234@gmail.comzvgjckJohnzvgjck5zvgjckDoezvgjck555-1234", "456 Oak Avenuezvgjckjane.smith5678@gmail.comzvgjckJanezvgjck6zvgjckSmithzvgjck555-5678", "789 Pine Roadzvgjckemily.johnson91011@gmail.com ...
```

| Address          | Email                        | First name | ID  | Last name | Phone    |
| ---------------- | ---------------------------- | ---------- | --- | --------- | -------- |
| 123 Maple Street | john.doe1234@gmail.com       | John       | 5   | Doe       | 555-1234 |
| 456 Oak Avenue   | jane.smith5678@gmail.com     | Jane       | 6   | Smith     | 555-5678 |
| 789 Pine Road    | emily.johnson91011@gmail.com | Emily      | 7   | Johnson   | 555-9012 |
| ...              | ...                          | ...        | ... | ...       | ...      |
<p align="center">
  <img src="./Assets/Image 5 - Attacket get customer credentials.webp" alt="Attacket get customer credentials" /> <br />
  <em>Image 5: Attacket get customer credentials</em>
</p>

The same happen with the `book` table in the packet 1658 & 1663.
<p align="center">
  <img src="./Assets/Image 6 - Attacket get book information.webp" alt="Attacket get book information" /> <br />
  <em>Image 6: Attacket get book information</em>
</p>

Then from `19:12:20` to `19:12:58` (packet 1685 to 88562), attacker use `robuster` to find all hidden assets of web server. He found the `/admin` page and login to `/admin/login.php` with admin credentials that found above `admin - admin123!`, so that he can access `/admin/index.php` page.
<p align="center">
  <img src="./Assets/Image 7 - Attacker access admin page.webp" alt="Attacker access admin page" /> <br />
  <em>Image 7: Attacker access admin page</em>
</p>

Then at about `19:24`, the attacker upload a file `NVri2vhp.php` to the server.
<p align="center">
  <img src="./Assets/Image 8 - Attacker upload malware.webp" alt="Attacker upload malware" /> <br />
  <em>Image 8: Attacker upload malware</em>
</p>

# Answer the Questions

**Q1: By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?**

It is `111.224.250.131`.

**Q2: If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?**

The attacker come from `Shijiazhuang, China`.

**Q3: Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable PHP script name?**

It is `search.php`.

**Q4: Establishing the timeline of an attack, starting from the initial exploitation attempt, what is the complete request URI of the first SQLi attempt by the attacker?**

The first SQLi attempt by the attacker is `book and 1=1; -- -` and full request is `/search.php?search=book and 1=1; -- -`.

**Q5: Can you provide the complete request URI that was used to read the web server's available databases?**

The complete requets URI that was used to read the web server's available databases is `/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -` in the packet 1520.

**Q6: Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?**

It is `customer` table.

**Q7: The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide the name of the directory discovered by the attacker?**

It is `/admin` page.

**Q8: Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?**

Attacker use admin account `admin - admin123!`.

**Q9: We need to determine if the attacker gained further access or control of our web server. What's the name of the malicious script uploaded by the attacker?**

Attacker upload malicious called `NVri2vhp.php`.