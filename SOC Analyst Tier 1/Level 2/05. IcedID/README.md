# Scenario & Objective

A cyber threat group was identified for initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payloads were IcedID. You have been given a hash of an IcedID sample to analyze and monitor the activities of this advanced persistent threat (APT) group.

- **Category**: Threat Intel
- **Tools**: VirusTotal

# Analysis

At first, I search in VirusTotal to verify this is the malware and it flagged as a trojan.
<p align="center">
  <img src="./Assets/Image 1 - Verify the malware.webp" alt="Verify the malware" /> <br />
  <em>Image 1: Verify the malware</em>
</p>

Then, I go to Detail tab to see more information about this malware like creation time and other name of malware.
<p align="center">
  <img src="./Assets/Image 2 - Creation time and other name of malware.webp" alt="Creation time and other name of malware" /> <br />
  <em>Image 2: Creation time and other name of malware</em>
</p>

Then I go to Relations tab to see the C2 server or something like this that the malware connect with.
<p align="center">
  <img src="./Assets/Image 3.1 - Malware connect URL.webp" alt="Malware connect URL" /> <br />
  <img src="./Assets/Image 3.2 - Malware connect domain.webp" alt="Malware connect domain" /> <br />
  <img src="./Assets/Image 3.3 - Malware connect IP.webp" alt="Malware connect IP" /> <br />
  <em>Image 3: Malware connect with C2 server</em>
</p>

Moreover, the `Bundled Files` section show all the files that stored in inside the malware that being studied.

# Answer the Questions

**Q1: What is the name of the file associated with the given hash?**

The name of malware that associated with the given hash is in the image 2, there are 5 different names of malware but only `document-1982481273.xlsm` match the answer format.

**Q2: Can you identify the filename of the GIF file that was deployed?**

From the "Contect URL" in the image 3, the filename of the GIF file that was deployed is `3003.gif`.

**Q3: How many domains does the malware look to download the additional payload file in Q2?**

There 15 domains that the malware connect with but only `5` domains that the malware look to download the additional payload file and it is flagged as red color.

**Q4: From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?**

From 5 domains are flagged in red color, there is only a registrar INC `NameCheap`.

**Q5: Could you specify the threat actor linked to the sample provided?**

From the mitre att&ck, the malware IcedID is used by group TA551 or `Gold Cabin`.
<p align="center">
  <img src="./Assets/Image 4 - Threat Actor linked to malware.webp" alt="Threat Actor linked to malware" /> <br />
  <em>Image 4: Threat Actor linked to malware</em>
</p>

**Q6: In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?**

From Behavior tab, the execution phase contain the function `URLDownloadToFileA`.
<p align="center">
  <img src="./Assets/Image 5 - Malware employ function to fetch extra payloads.webp" alt="Malware employ function to fetch extra payloads" /> <br />
  <em>Image 5: Malware employ function to fetch extra payloads</em>
</p>