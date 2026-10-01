# Scenario & Objective

As a diligent cyber threat hunter, your investigation begins with a hypothesis: 'Recent trends suggest an upsurge in Kerberoasting attacks within the industry. Could your organization be a potential target for this attack technique?' This hypothesis lays the foundation for your comprehensive investigation, starting with an in-depth analysis of the domain controller logs to detect and mitigate any potential threats to the security landscape.

Note: Your Domain Controller is configured to audit Kerberos Service Ticket Operations, which is necessary to investigate kerberoasting attacks. Additionally, Sysmon is installed for enhanced monitoring.

- **Category**: Threat Hunting
- **Tools**: Splunk, VirusTotal
## Overview
(Conclude your report with a summary of the main finding of you analysis --> 5 Ws: Who, What, When, Where, Why)

# Analysis

The screnario said that the DC is configured to audit Kerberos Service Ticket Operation. So I check for all event ID and the system has some ID relate to Kerberos protocol:

- `4768`: A Kerberos authentication ticket (TGT) was requested.
- `4769`: A Kerberos service ticket was requested.

```SPL
index="kerberoasted"
| stats count by event.code
```
<p align="center">
  <img src="./Assets/Image 1 - EventID relate to Kerberos protocol.png" alt="EventID relate to Kerberos protocol"/><br/>
  <em>Image 1: EventID relate to Kerberos protocol</em>
</p>

The screnario suggest the Kerberoasting attack within industry. I also want to verify this so I check the Kerberos encryption type `0x17` stand for `RC4-HMAC`, which is suitable with Kerberoasting technique.
<p align="center">
  <img src="./Assets/Image 2 - Keberos encryption type.png" alt="Keberos encryption type"/><br/>
  <em>Image 2: Keberos encryption type</em>
</p>

Moreover, with the Kerberoasting technique and weak encryption, I know I need to filter with event ID 4769. Then I found suspicious users `johndoe` target sensitive service `SQLService` and `FileShareService` within a short timeframe in `2023-10-16`.
```SPL
index="kerberoasted" event.code=4769
| table @timestamp winlog.event_data.TargetUserName winlog.event_data.ServiceName
```
<p align="center">
  <img src="./Assets/Image 3 - Suspicious user in a short timeframe.png" alt="Suspicious user in a short timeframe"/><br/>
  <em>Image 3: Suspicious users</em>
</p>

Moreover the services was logged in from IP `10.0.0.154` at `07:37:34`. And it also sent request at the same time. These actions are so suspicious because it suggests a possible automated or scripted process.
```SPL
index="kerberoasted" event.code=4624 winlog.event_data.IpAddress=10.0.0.154
| table @timestamp, winlog.event_data.TargetUserName
```
<p align="center">
  <img src="./Assets/Image 4.1 - Login attempt.png" alt="Login attempt"/><br/>
  <img src="./Assets/Image 4.2 - Machine IP address.png" alt="Machine IP address"/><br/>
  <em>Image 4: Login attempt</em>
</p>

Then at about `07:50`, there is a request from `SQLService` to `DC01`. These actions are so suspicious and can be indicator of compromised.
<p align="center">
  <img src="./Assets/Image 5 - IoC compromised service account.png" alt="IoC compromised service account"/><br/>
  <em>Image 5: IoC compromised service account</em>
</p>

These verify that the attacker has initiall access to host with IP `10.0.0.154`, then he used Kerberoasting technique to offline crack the password of SQL service. However, I don't know how attacker have initiall access into host `10.0.0.154`.

Based on the information above, I filter with login attemp of IP `10.0.0.154`. Then I found that beside the `johndoe` and `SQLService`, this IP also login into account `MARKETINGPC$`.
```SPL
index="kerberoasted" event.code=4624 winlog.event_data.IpAddress=10.0.0.154
| table @timestamp, winlog.event_data.TargetUserName
```
<p align="center">
  <img src="./Assets/Image 6 - Another victim.png" alt="Another victim"/><br/>
  <em>Image 6: Another victim</em>
</p>

Follow the timeline, I want to know what did he do in DC01 with SQL service account, so I filter with timestamp `2023-10-16T07:37:34`. There are multiple event code and here are some event code that I can found suspicious information.

| Event Code | Name                                  | Provider              |
| ---------- | ------------------------------------- | --------------------- |
| 1          | Process Creation                      | Sysmon                |
| 3          | Network Connection                    | Sysmon                |
| 6          | Driver Loaded                         | Sysmon                |
| 11         | File Create                           | Sysmon                |
| 12, 13, 14 | Registry Events                       | Sysmon                |
| 18         | Named Pipe connected                  | Sysmon                |
| 19, 20     | WMI Events                            | Sysmon                |
| 4799       | Security Group Membership Enumeration | Windows Security Logs |
| 7045       | A service was installed in the system | Windows Security Logs |

At first, I filter with event code 1 - Process creation. 
```SPL
index="kerberoasted" @timestamp>=2023-10-16T07:37:34 event.code=1
| table @timestamp, winlog.event_data.ParentCommandLine, winlog.event_data.CommandLine, winlog.event_data.ParentProcessId, winlog.event_data.ProcessId, winlog.event_data.Hashes
```


# Answer the Questions

**Q1: To mitigate Kerberoasting attacks effectively, we need to strengthen the encryption Kerberos protocol uses. What encryption type is currently in use within the network?**

The encryption type is `RC4-HMAC`.

**Q2: What is the username of the account that sequentially requested Ticket Granting Service (TGS) for two distinct application services within a short timeframe?**

The correct answer is `johndoe`.

**Q3: We must delve deeper into the logs to pinpoint any compromised service accounts for a comprehensive investigation into potential successful kerberoasting attack attempts. Can you provide the account name of the compromised service account?**

The account name of the compromised service account is `SQLService`.

**Q4: To track the attacker's entry point, we need to identify the machine initially compromised by the attacker. What is the machine's IP address?**

The machine IP address is `10.0.0.154.

**Q5: To understand the attacker's actions following the login with the compromised service account, can you specify the service name installed on the Domain Controller (DC)?**

**Q6: To grasp the extent of the attacker's intentions, What's the complete registry key path where the attacker modified the value to enable Remote Desktop Protocol (RDP)?**

**Q7: To create a comprehensive timeline of the attack, what is the UTC timestamp of the first recorded Remote Desktop Protocol (RDP) login event?**

**Q8: To unravel the persistence mechanism employed by the attacker, what is the name of the WMI event consumer responsible for maintaining persistence?**

**Q9: Which class does the WMI event subscription filter target in the WMI Event Subscription you've identified?**