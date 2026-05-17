# Scenario & Objective

You have been tasked by a client whose network was compromised and brought offline to investigate the incident and determine the attacker's identity.

Incident responders and digital forensic investigators are currently on the scene and have conducted a preliminary investigation. Their findings show that the attack originated from a single user account, probably, an insider. Investigate the incident, find the insider, and uncover the attack actions.

I was provided a folder contain 3 information: Link to her github, office.jpg and WebCam.jpg.

- **Category**: Threat Intel
- **Tools**: Google
# Overview
(5 Ws: Who, What, When, Where, Why)
# Analysis

From the repositories in the Emarseille99 github, I found the list of her repositories:

- **Project-Build---Custom-Login-Page**: Her working project.
- **Meterpeter**: This is an advanced, dynamically extensible payload included in the Metasploit Framework.
- **Metasploit-framework**: This is an open-source, Ruby-based modular platform used by security professionals for penetration testing, vulnerability validation, and exploit development.
- **QuasarRAT**: This is a lightweight, open-source administration tool originally designed for legitimate IT support, system administration, and employee monitoring.
- **Hashcat**: This is a fast, open-source, and advanced password recovery tool used for security auditing and penetration testing.
- **Nmap**: This is a tool for network discovery and security auditing, used to scan computer networks for hosts, services, and operating systems.
- **Empire**: This is C2 framework, which designed for security professionals to emulate adversary behavior and test network defenses.
- **Mimikatz**: This is powerful credential-dumping tool used to extract plain-text passwords, hashes, PINs, and Kerberos tickets from Windows memory.
- **PoshC2**: This is C2 framework designed for penetration testing and red teaming, allowing security professionals to perform post-exploitation and lateral movement.
- **BloodHound**: This is penetration testing and security auditing tool that uses graph theory to map hidden relationships and attack paths within Microsoft Active Directory (AD) environments.
- **XploitSPY**: This is an android RAT that help user gain unauthorized access to Android devices, allowing attackers to exfiltrate vast amounts of personal information and monitor user activity in real-time.
- **Xmrig**: This is a high-performance, open-source software tool used for mining cryptocurrencies
- **Responder**: This is a Link Local Multicast Name Resolution (LLMNR), NBT-NS, and MDNS poisoner.
- **Mirai-Source-Code**: This is the botnet.

But only `Project-Build---Custom-Login-Page` repo has description as `Working`. Other repositories forked from some where so that is not her project. 
<p align="center">
  <img src="Image 1 - Sensitive project public.webp" alt="Sensitive project public" /> <br />
  <em>Image 1: Sensitive project public</em>
</p>
When I check the `Login Page.js` of the project, I found the `API Key = aJFRaLHjMXvYZgLPwiJkroYLGRkNBW`. 

I also found the creadential of her:
```leakCreadentials
Username: EMarseille99
Password: UGljYXNzb0JhZ3VldHRlOTk=
Password(base64)
```

That is all I can found on her project, not so much. Then I use `sherlock` to search for social media of her, and I foud this:
```SocialMedia
A problem occurred while checking for an update: 'tag_name'
[*] Checking username EMarseille99 on:

[+] Cults3D: https://cults3d.com/en/users/EMarseille99/creations
[+] GitHub: https://www.github.com/EMarseille99
[+] Steam Community (User): https://steamcommunity.com/id/EMarseille99/
[+] TikTok: https://www.tiktok.com/@EMarseille99
[+] Trovo: https://trovo.live/s/EMarseille99/

[*] Search completed with 5 results
```

It seems nothing special. Then I decide to find the location of her images `WebCam.png`, `office.png`.

- `WebCam.png`: This is a live aerial view of the University of Notre Dame campus, captured by an EarthCam mounted on the university's Main Building.
- `office.png`: This image features the entrance to Birmingham New Street railway station and the attached Grand Central shopping complex.
# Answer the Questions

**Q1: File -> Github.txt: What API key did the insider add to his GitHub repositories?**

`API Key = aJFRaLHjMXvYZgLPwiJkroYLGRkNBW`. 

**Q2: File -> Github.txt: What plaintext password did the insider add to his GitHub repositories?**

I found `Password: UGljYXNzb0JhZ3VldHRlOTk` in her repository. This is base64 encode. After decoding, the paintext password is `PicassoBaguette99`.

**Q3: File -> Github.txt: What cryptocurrency mining tool did the insider use?**

From the list of repositories above, the cryptocurrency mining tool is `Xmrig`.

**Q4: On which gaming website did the insider have an account?**

From `sherlock` tool above, I found that she uses `Steam` for gaming.

**Q5: What is the link to the insider Instagram profile?**

I search on instagram and found her profile: `https://www.instagram.com/emarseille99/`.

After researching, I found that the tool `sherlock` cannot find her instagram profile because Instagram actively blocks automated bots and scripts from bulk-probing their servers. When Sherlock tries to ping Instagram to see if a username is claimed, Instagram rejects the request or redirects the bot to a login page, causing Sherlock to mark it as not found

**Q6: Which country did the insider visit on her holiday?**

From her instagram profile, I foun a post that she wrote "Once in a lifetime holiday here, love me some slings x". It is absolutely the information I need to find. That is Marina Bay Sands hotel in the Singapore.

**Q7: Which city does the insider family live in?**

Also form her instagram profile, I found her post "Nice to meet friends & family Photo" with 2 image. After researching, I know her family lived in Dubai.

**Q8: File -> office.jpg: You have been provided with a picture of the building in which the company has an office. Which city is the company located in?**

From information I analysed above, I know the company located in Birmingham, Engliand.

**Q9: File -> Webcam.png: With the intel, you have provided, our ground surveillance unit is now overlooking the person of interest suspected address. They saw them leaving their apartment and followed them to the airport. Their plane took off and landed in another country. Our intelligence team spotted the target with this IP camera. Which state is this camera in?**

After researching, I found the image capture University of Notre Dame campus, located in Notre Dame, Indiana.