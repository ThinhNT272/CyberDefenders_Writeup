# Scenario & Objective

A finance company's Azure environment has flagged multiple failed login attempts from an unfamiliar geographic location, followed by a successful authentication. Shortly after, logs indicate access to sensitive Blob Storage files and a virtual machine start action. Investigate authentication logs, storage access patterns, and VM activity to determine the scope of the compromise.

- **Category**: Cloud Forensics
- **Tools**: ELK

## Overview

The attack phase happened in `2023-10-05` to `2023-10-06` by 2 compromised account `alice` and `IT Admin`. Furthermore, he also created an fake account called 'IT Support' for persistent access. 

For more detail, at about `2023-10-05 14:30`, account `alice` was compromised, by some how attacker know the alice's credentials, so that he can access the Azure. After successfully log-in account `alice`, attacer use something like VPN to swith the location from US to Germany. Then at about `15:14 - 15:18`, attacker (use account `alice` with "Storage Blob Data Reader" permission) access sensitive information in Blob Storage files as below:

- `GetBlobServiceProperties`: Get the configuration of Blob Storage.

- `ListBlobs`: List all files in Blobs.

- `GetBlobmetadata`: Read a metadata of file `service-config.ps1`.

- `GetUserDelegationKey`:  This action requets a User Delegation Key so that "alice" can generate SAS Token for any file in Blob Storage.

- `GetBlobTags`: This action read key-valye tags of file Blob.

- `GetBlob`: Attacker read or download a file `service-config.ps1` in blob.

After getting some information from Blob Storage, attacker has the account `IT Admin`'s credentials maybe he already know or maybe by the file `service-config.ps1` that he got from Blob above. So that, at about `15:23`, attacker can has successfully authentication  account `IT Admin`.

This account has `Owner` permission - highest permission, so that attacker can do many actions in `2023-10-05:

- `15:24` - `MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION`: This action turn on a virtual machine called `DEV01VM`.

- `15:26` - `MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION`: This action use "IP Flow Verify" feature of Azure Network Watcher. This feature checks a specific IP or Port are denied by Network Security Group - NSG. 

- `15:33` - `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`: This action list Access Key of Storage Account. The target is group `RSS1` in storage accoutn `CACTUSSTORAGE2023`.

- `15:33` - `MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION`: This action exports SQL database into "file.bacpac" in store into Storage Account. He targeted to database `CustomerDataDB` in SQL server `CACTUSDBSERVER`.

- `15:42` - `Add User`: Usser `IT Support` was created by `IT Admin`.

- `15:44` - `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`: This action add a role to an object (user, group, ...) in Azure RBAC (Role-Based Access Control). Attacker add role `Owner` with scope is entire `subcription` to an account `IT Support`.

Then in the `2023-10-06 07:29`, attacker use `IT Admin` account to change password of account `IT Support`. He also logged-in into account `IT Support`, account was logged-in the first time in Azure create an action called `Update StsRefreshTokenValidFrom Timestamp`.

Finally, in  the `2023-10-06`, at `07:30` attacker change password of `IT Support` (self-service) and log-in agains.

# Analysis

The ELK contains 348 events from `2023-10-05` to `2023-10-06`. 

As I know there are an alert of multiple failed login attempts from an unfamiliar geographic location, so I filter with field `azure.signinlogs.properties.token_issuer_type` that contains 159 events of AzureAD. These logs capture authentication and authorization events, providing insights into login attempts and credential usage. I also add field `event.action.keyword: Sign-in activity` `event.outcome.keyword: failure` to idenfy who is the most failed login attempts.
<p align="center">
  <img src="./Assets/Image 1 - Failed login attempts.webp" alt="Failed login attempts" /> <br />
  <em>Image 1: Failed login attempts</em>
</p>

 There are nothing suspicious here, all login attemps are not different significantly. So I filter with another way that find an unfamiliar geographic location.
 <p align="center">
  <img src="./Assets/Image 2 - Unfamiliar geographic location.webp" alt="Unfamiliar geographic location" /> <br />
  <em>Image 2: Unfamiliar geographic location</em>
</p>

From the image above, there are 2 unfamiliar geographic location Germany with 26 events and France with 3 events. As the alert said "Shortly after, logs indicate access to sensitive Blob Storage files and a virtual machine start action", 3 events from France is too small for attacker can do anything. So the suspicious geographic location here is `Germany`. 

But when I filter with log-in activities like above, I cannot find any failed log-in action. All the log-in activities from Germany is successfull, it is not match the scenario. All the failed log-in attempt are come from United States at about. In my opinion, this is because attacker use something like VPN from US when he try to brute-force, and when he has the credentials, he switch to VPN from Germany and access the system.
<p align="center">
  <img src="./Assets/Image 3 - No failed sign-in act in Germany.webp" alt="No failed sign-in act in Germany" /> <br />
  <em>Image 3: No failed sign-in action in Germany</em>
</p>

And from 13 events, there are 3 users  `IT Admin`, `IT Support`, `alice` has sign-in activities. There 3 suspicious accounts.
<p align="center">
  <img src="./Assets/Image 4 - Suspicious users.webp" alt="Suspicious users" /> <br />
  <em>Image 4: Suspicious users</em>
</p>

Moreover, follow the scenario, I filter with action start virtual machine in unfamiliar geography and I found the attacker compromised account `IT Admin`. 

```
source.geo.country_name.keyword: "Germany"  and event.action.keyword : "MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION" 
```

<p align="center">
  <img src="./Assets/Image 5 - Attacker compromised admin account.webp" alt="Attacker compromised admin account" /> <br />
  <em>Image 5: Attacker compromised admin account</em>
</p>

Then I want to know everything the account `IT Admin` did in the system beside the start virtual machine activity. And I got this.
<p align="center">
  <img src="./Assets/Image 6 - Attacker actions.webp" alt="Attacker actions" /> <br />
  <em>Image 6: Attacker actions</em>
</p>

- `Oct 5, 2023 15:24` - `MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION`: This action turn on a virtual machine called `DEV01VM`. The account has `Owner` - highest permision in subscription.

- `Oct 5, 2023 15:26` - `MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION`: This action use "IP Flow Verify" feature of Azure Network Watcher. This feature checks a specific IP or Port are denied by Network Security Group - NSG. 

- `Oct 5, 2023 15:33` - `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`: This action list Access Key of Storage Account. This Access Key help user fully read/write data in Storage Account. The target is group `RSS1` in storage accoutn `CACTUSSTORAGE2023`.
<p align="center">
  <img src="./Assets/Image 7 - Target storage.webp" alt="Target storage" /> <br />
  <em>Image 7: Target storage</em>
</p>

- `Oct 5, 2023 15:33` - `MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION`: This action exports SQL database into "file.bacpac" in store into Storage Account. He targeted to database `CustomerDataDB` in SQL server `CACTUSDBSERVER`.

- `Oct 5, 2023 15:44` - `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`: This action add a role to an object (user, group, ...) in Azure RBAC (Role-Based Access Control). Attacker add role `Owner` with scope is entire subcription to an account has id `99000683-91fc-40ea-b942-87868f0eadcd`.
<p align="center">
  <img src="./Assets/Image 8 - Attacker prepare persistent attack.webp" alt="Attacker prepare persistent attack" /> <br />
  <em>Image 8: Attacker prepare persistent attack</em>
</p>


This is a common tactic, attacker create a fake credentials and add highest permission to that account so that he can get persistent access into system. But what is the fake account is? And when was it created? To know this, I filter with the credential id in entire logs.

So I got 8 events as the image 9 below.
<p align="center">
  <img src="./Assets/Image 9 - Fake credential action.webp" alt="Fake credential action" /> <br />
  <em>Image 9: Fake credential action</em>
</p>

By checking each event, I found that at about `Oct 5, 2023 15:42:53.53`, an user `IT Support` was created by `IT Admin`. I really don't know why this event did not appear when I querry "IT Admin" above. 

However, at about `Oct 6, 2023 07:29`, "IT Admin" change password of account "IT Support". Then account "IT Support" has an action `Update StsRefreshTokenValidFrom Timestamp`. This indicates that the attacker does not use account "IT Admin" anymore and switch to account "IT Support" to access the system. And In `Oct 6, 2023, at 07:30` attacker change password of "IT Support" and log-in agains.

Moreover, I found some failed sign-in activity from account "IT Admin" at about `Oct 5, 2023 14:33 - 14:56`. 

In here, I relize that 2 accoutns "IT Admin" or "IT Support" above don't have any activity access to sensitive Blob Storage file as Scenario. So I search for `blob` in entire logs, and I found account `alice`. 
<p align="center">
  <img src="./Assets/Image 10 - Alice access Blob.webp" alt="Alice access Blob" /> <br />
  <em>Image 10: Alice access Blob</em>
</p>

At about `Oct 5, 2023 15:14 - 15:18`, account "alice" with "Storage Blob Data Reader" permission access sensitive Blob Storage file as below:

- `GetBlobServiceProperties`: Get the configuration of Blob Storage.

- `ListBlobs`: List all files in Blobs.

- `GetBlobmetadata`: Read a metadata of file `service-config.ps1`.

- `GetUserDelegationKey`:  This action requets a User Delegation Key so that "alice" can generate SAS Token for any file in Blob Storage.

- `GetBlobTags`: This action read key-valye tags of file Blob.

- `GetBlob`: Attacker read or downloaded a file 'service-config.ps1' in blob.

So "alice" is also a compromised account. But how he can get into accont alice.

After filtering, in `Oct 5, 2023`, the system recorded a anormal sign-in action from "alice". There are the reson of 3 request failure:

- `14:30:26` (Error Code 50140) - `This error occurred due to 'Keep me signed in' interrupt when the user was signing-in`.

- `14:30:27` (Error Code 50126) - `Invalid username or password on-premise username or password`.

- `14:31:11` (Error Code 50072) - `Due to a configuration change by your administrator, or because you moveed to a new location, you must enroll in multi-factor authentication to access the tenant (MFA required in Azure AD)`.

<p align="center">
  <img src="./Assets/Image 11 - Attacker access account alice.webp" alt="Attacker access account alice" /> <br />
  <em>Image 11: Attacker access account alice</em>
</p>

From 3 login-attemps above, I assume that attacker access by cookie by `alice`. Because in the first failed log-in, the error message appear `Keep me signed in`, this means this log-in use the expire cookie of account `alice`. He doesn't know the correct password because of the second failed log-in `invalid username or password`. And in the 3rd failed log-in, it seems like attacker use new cookie and access system, but because of the unfamiliar geographic, the account need to enroll MFA.

However, attacker still by pass the protection and access the system, evidence is he can access sensitive Blob Storage as above.

Then I go back to answer the question how attacket can get account "IT Admin" above. From the accoutn "IT Admin" activities, at `Oct 5, 2023 15:23`, after attacker get file `service-config.ps1`, there is an successful authentication. So in my opinion, there is an account's credentials of "IT Admin" in the file `service-config.ps1`.
<p align="center">
  <img src="./Assets/Image 12 - Attacker access account IT Admin.webp" alt="Attacker access account IT Admin" /> <br />
  <em>Image 12: Attacker access account IT Admin</em>
</p>

# Answer the Questions

**Q1: As a US-based company, the security team has observed significant suspicious activity from an unusual country. What is the name of the country from which the attack originated?**

It is `Germany`.

**Q2: To establish an accurate incident timeline, what is the timestamp of the initial activity originating from the country?**

It is `2023-10-05 15:09`.

**Q3: To assess the scope of compromise, we must determine the attacker's entry point. What is the display name of the compromised user account?**

It is `alice`.

**Q4: To gain insights into the attacker's tactics and enumeration strategy, what is the name of the script file the attacker accessed within blob storage?**

It is `service-config.ps1`.

**Q5: For a detailed analysis of the attacker's actions, what is the name of the storage account housing the script file?**

It is `cactusstorage2023`.

**Q6: Tracing the attacker's movements across our infrastructure, what is the User Principal Name (UPN) of the second user account the attacker compromised?**

It is `it.admin1@cybercactus.onmicrosoft.com`.

**Q7: Analyzing the attacker's impact on our environment, what is the name of the Virtual Machine (VM) the attacker started?**

It is `Dev01VM`.

**Q8: To assess the potential data exposure, what is the name of the database exported?**

It is `CustomerDataDB`.

**Q9: In your pursuit of uncovering persistence techniques, what is the display name associated with the user account you have discovered?**

It is `IT Support`.

**Q10: The attacker utilized a compromised account to assign a new role. What role was granted?**

It is `Owner`.

**Q11: For a comprehensive timeline and understanding of the breach progression, What is the timestamp of the first successful login recorded for this user account?**

It is `2023-10-06 07:30`.
