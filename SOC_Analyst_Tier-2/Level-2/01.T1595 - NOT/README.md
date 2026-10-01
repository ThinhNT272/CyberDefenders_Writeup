# Scenario & Objective

Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. In these scans, the adversary probes the victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.

Adversaries may perform different forms of active scanning depending on what information they seek to gather. These scans can also be performed in various ways, including using native features of network protocols such as ICMP. Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).

- **Category**: Network Forensics
- **Tools**: Wireshark, VirusTotal

Code sample for image:
<p align="center">
  <img src="./Assets/abc.png" alt="abc"/><br/>
  <em>Image 1: abc</em>
</p>

## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

The PCAP file contain 3358 packets from `04:19:09` to `05:21:15` in `06-25-2022`. And the hash of PCAP file is `f09a62e0387bc2bb2bffbeeabfffc899e9f5da9f0d94ab9896d6519c0ee0f51f`.

# Answer the Questions

**Q1: What is the Zero-tier network ID?**

**Q2: What is the size of ARP packets in bytes?**

**Q3: What is the address that sent the most packets?**

**Q4: What is the City of the IP is connected to in the Philippines?**

**Q5: How many DHCP Discover messages are in the PCAPNG file?**

**Q6: What is the "Target MAC address" for packet 37?**

**Q7: How many ARP reply packets are present in the PCAPNG file?**

**Q8: What is the time packet 55 sent?**

**Q9: What is the range of the targeted network IP addresses?**

**Q10: What are the port numbers targeted by the attacker?**

**Q11: What is the country where the attacker is located?**

**Q12: What is the name of the Threat Actor with which this technique is associated?**