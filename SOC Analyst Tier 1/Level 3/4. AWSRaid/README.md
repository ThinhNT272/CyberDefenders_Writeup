# Scenario & Objective

Your organization utilizes AWS to host critical data and applications. An incident has been reported that involves unauthorized access to data and potential exfiltration. The security team has detected unusual activities and needs to investigate the incident to determine the scope of the attack.

- **Category**: Cloud Forensics
- **Tools**: Splunk

## Overview

During a security investigation of AWS CloudTrail logs in Splunk, a critical cloud security incident was analyzed. Below is the conclusion of the analysis.

An external attacker compromised the AWS IAM user account `helpdesk.luke` (which lacked Multi-Factor Authentication (MFA) protection). To establish long-term persistence, the attacker later created a rogue backdoor IAM account named `marketing.mark` and escalated its privileges by adding it to the `Admins` group.

The attacker accessed S3, read 6 sensitive files, and downloaded 2 objects (including a customer data backup archive). Finally, they executed IAM reconnaissance and created a backdoor administrative account.

These happenned on Thursday 11/02/2023, the attack took place in the organization's AWS cloud environment, targeting console log-ins, the IAM service, and multiple sensitive S3 storage.

For more information, at about `07:37 - 09:55`, The attacker initiated the intrusion by logging into the AWS Console using `helpdesk.luke`, generating 10 failed login attempts prior to a successful authentication. Then he try to access resources as below.

| Timestamp    | Attacker Activity       | Files                                  | Files's Host                                                  |
| ------------ | ----------------------- | -------------------------------------- | ------------------------------------------------------------- |
| `9:55:53.00` | Read                    | prototype.obj                          | research-project-files23411723.s3.us-east-1.amazonaws.com     |
| `9:56:07.00` | Read                    | Product2_CAD_Designs.dwg               | product-designs-repository31183937.s3.us-east-1.amazonaws.com |
| `9:56:20.00` | Download (77 537 Bytes) | logo.png                               | marketing-assets-vault27512203.s3.us-east-1.amazonaws.com     |
| `9:56:30.00` | Read                    | Contract_Agreement.pdf                 | legal-docs45020393.s3.us-east-1.amazonaws.com                 |
| `9:56:39.00` | Download (24 Bytes)     | CustomerData_Backup_2023-11-01.zip     | customer-data-backup57893984.s3.us-east-1.amazonaws.com       |
| `9:56:50.00` | Read                    | Contract_Termination_Letter_Client.pdf | contracts-data67988444.s3.us-east-1.amazonaws.com             |
| `9:57:04.00` | Read                    | Configuration_Backup_Server2.zip       | backup-and-restore98825501.s3.us-east-1.amazonaws.com         |
| `9:57:11.00` | Read                    | secrets_vault_dump.bak                 | backup-and-restore98825501.s3.us-east-1.amazonaws.com         |

Then, as I said above, attacker create rogue user called `marketing.mark` and add it into group `Admins` at about `9:59`.

The primary objectives were `data exfiltration` of sensitive information (CAD designs, client contracts, database backups, and customer backups) and `persistence establishment` (creating a backdoor administrator account) to secure unrestricted, stealthy access for future operations.

# Analysis

First, I filter `index=*` to see all fields in the Splunk. Then I know some fileds:

- 1 host `splunk`
- 1 sourcetype `aws:cloudtrail`
- 23 eventSource with `s3.amazonaws.com` is the most triggerd logs with `2 702` events, obtained about `67%`.
<p align="center">
	  <img src="./Assets/Image 1 - eventSource.webp" alt="eventSource" /> <br />
  <em>Image 1: eventSource</em>
</p>

- 3 eventType. But I know that the security team has detected unusual activities from scenario. So I focus on sign-in activities.
<p align="center">
	  <img src="./Assets/Image 2 - eventType.webp" alt="eventType" /> <br />
  <em>Image 2: eventType</em>
</p>

Then, I filter with `AwsConsoleSignIn` eventType. There are total 35 events and 12 people try to log-in through userIdentity.userName field. 
<p align="center">
	  <img src="./Assets/Image 3 - User log-in.webp" alt="User log-in" /> <br />
  <em>Image 3: User log-in</em>
</p>

I find user `helpdesk.luke` has 12 log-in activities. Quite suspicious because it is significantly more than other user.

I also see the errorMessage field. There is only `Failed authentication` value in 19/35 events.
<p align="center">
	  <img src="./Assets/Image 4 - Error mesage.webp" alt="Error mesage" /> <br />
  <em>Image 4: Error mesage</em>
</p>

So I filter with this field with command `index=* eventType=AwsConsoleSignIn errorMessage="Failed authentication"`. Then I find 6 people failed at log-in.
<p align="center">
	  <img src="./Assets/Image 5 - User failed log-in.webp" alt="User failed log-in" /> <br />
  <em>Image 5: User failed log-in</em>
</p>

One again, user `helpdesk.luke` failed log-in 10 times, more than 3 times other people. Too suspicious, so I fiter with him `index=* userIdentity.userName=helpdesk.luke` to know what did he do in the system.

There is 480 events and all appear on `Thurday` (date_wday field) `11/02/2023`(date_mday, date_month, date_years fields) from `7:37 - 9:59` (date_hour, date_minute fields).

From evenSource, I find that he mostly access to `s3` and `iam`. After researching, I found some suspicious activities of `s3` and `iam`. But I will filter with source `s3` first.
<p align="center">
	  <img src="./Assets/Image 6 - eventSource potential compromised.webp" alt="eventSource potential compromised" /> <br />
  <em>Image 6: eventSource potential compromised</em>
</p>

## What did attacker do in S3

I want to check all actions that he made. So I filter with the command below to see all activities was made by attacker.

```SPL
index=* userIdentity.userName=helpdesk.luke eventSource="s3.amazonaws.com"
| stats count by eventName
```

There are 16 eventName and I will briefly describe below:

| eventName                             | Count | Briefly Description                                                                                                                                           |
| ------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GetAccountPublicAccessBlock`         | 10    | It tells the inquirer whether the account has enabled the feature to block all public access configurations (such as public ACLs or public bucket policies)   |
| `GetBucketAcl`                        | 18    | User requests the Access Control List (ACL) of an Amazon S3 bucket to checks who has read/write permissions to that specific bucket                           |
| `GetBucketCors`                       | 2     | It tracks a user or application querying the Cross-Origin Resource Sharing (CORS) configuration of an Amazon S3 bucket                                        |
| `GetBucketOwnershipControls`          | 13    | User or application queried the Amazon S3 Object Ownership controls for a specific storage bucket                                                             |
| `GetBucketPolicy`                     | 2     | It represents the exact moment an AWS identity (user or role) requested to retrieve or view the access permissions attached to a specific Amazon S3 bucket    |
| `GetBucketPolicyStatus`               | 16    | It represents the event where an AWS user or service requests the policy status of an Amazon S3 bucket to check if the bucket is publicly accessible          |
| `GetBucketPublicAccessBlock`          | 23    | It represents an AWS API call where a user, role, or automated service is requesting to view the "Public Access Block" configuration for a specific S3 bucket |
| `GetBucketVersioning`                 | 9     | User requests to view the versioning status of an S3 bucket                                                                                                   |
| `GetObject`                           | 8     | It indicates that an IAM user or role has accessed, downloaded, or read an object from an Amazon S3 bucket                                                    |
| `GetStorageLensConfiguration`         | 20    | represents a `read` management event indicating a user or service requested to view the configuration details of an Amazon S3 Storage Lens                    |
| `GetStorageLensDashboardDataInternal` | 20    | It represents an API call made to retrieve metrics and analytics data for an Amazon S3 Storage Lens dashboard                                                 |
| `HeadBucket`                          | 8     | It uses to determine if an S3 bucket exists and if you have permission to access                                                                              |
| `ListAccessPoints`                    | 16    | It represents an API action that lists the Amazon S3 Access Points associated with an AWS account or a specific S3 bucket                                     |
| `ListBuckets`                         | 13    | It indicates that an AWS user or service has requested a list of all Amazon S3 buckets associated with your AWS account                                       |
| `ListObjects`                         | 7     | It represents the API call used to list the contents of an S3 bucket                                                                                          |
| `PutBucketPublicAccessBlock`          | 1     | It represents an API call made to AWS indicating that a user has created or modified the Block Public Access configuration for an Amazon S3 bucket            |

So, to know what attacker did, I will filter with `eventName="GetObject"`. There are 8 events from `9:55` to `9:57` in `11/02/2023`. Then from requestParameters.key field - which represents the exact S3 object path (file name) that was affected by an AWS API request, such as uploading, deleting, or downloading a file - I find 8 files that attacker try to get.
<p align="center">
	  <img src="./Assets/Image 7 - requestParameters.key of attacker in S3.webp" alt="requestParameters.key of attacker in S3" /> <br />
  <em>Image 7: Attacker try to get document in S3 bucket</em>
</p>

But I want to know detail about attacker activities, he just read or downloaded or modified anything, so I check for additionalEventData.bytesTransferredIn field.
<p align="center">
	  <img src="./Assets/Image 8 - DataIn.webp" alt="DataIn" /> <br />
  <em>Image 8: DataIn</em>
</p>

The value is `0`, which means the attacker did not modified anything. Then I check field additionalEventData.bytesTransferredOut.
<p align="center">
	  <img src="./Assets/Image 9 - DataOut.webp" alt="DataOut" /> <br />
  <em>Image 9: DataOut</em>
</p>

From the image above, I know that he read 6 files and downloaded 2 files. So which file did he read? Where is it from? I research 8 event and summarize as below

| Timestamp    | Attacker Activity       | Files                                  | Files's Host                                                  |
| ------------ | ----------------------- | -------------------------------------- | ------------------------------------------------------------- |
| `9:55:53.00` | Read                    | prototype.obj                          | research-project-files23411723.s3.us-east-1.amazonaws.com     |
| `9:56:07.00` | Read                    | Product2_CAD_Designs.dwg               | product-designs-repository31183937.s3.us-east-1.amazonaws.com |
| `9:56:20.00` | Download (77 537 Bytes) | logo.png                               | marketing-assets-vault27512203.s3.us-east-1.amazonaws.com     |
| `9:56:30.00` | Read                    | Contract_Agreement.pdf                 | legal-docs45020393.s3.us-east-1.amazonaws.com                 |
| `9:56:39.00` | Download (24 Bytes)     | CustomerData_Backup_2023-11-01.zip     | customer-data-backup57893984.s3.us-east-1.amazonaws.com       |
| `9:56:50.00` | Read                    | Contract_Termination_Letter_Client.pdf | contracts-data67988444.s3.us-east-1.amazonaws.com             |
| `9:57:04.00` | Read                    | Configuration_Backup_Server2.zip       | backup-and-restore98825501.s3.us-east-1.amazonaws.com         |
| `9:57:11.00` | Read                    | secrets_vault_dump.bak                 | backup-and-restore98825501.s3.us-east-1.amazonaws.com         |

## What did attacker do in IAM

When I filter with `eventSource="iam.amazonaws.com"`, there are 179 events from `9:58:44` to `9:59:53`. Similar as in `s3`, I check eventName field to see what did he do in this host. There are 18 eventName with briefly description as below.

| eventName                 | Count | Briefly Description                                                                                                    |
| ------------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------- |
| AddUserToGroup            | 1     | Someone add user to group                                                                                              |
| AttachUserPolicy          | 1     | someone gave user additional permissions                                                                               |
| CreateLoginProfile        | 1     | This identifies the creation of a login profile for one AWS user by another                                            |
| CreateUser                | 1     | A new user account has just been created in the system                                                                 |
| GetAccessKeyLastUsed      | 29    | It records someone checking when a specific AWS Access Key was last used                                               |
| GetAccountPasswordPolicy  | 1     | Someone queried AWS account to retrieve its password strength requirements                                             |
| GetAccountSummary         | 1     | User requested a high-level overview of the AWS account's IAM resources.                                               |
| GetGroup                  | 1     | User has requested the details of a specific IAM group, including its list of members                                  |
| GetLoginProfile           | 15    | User has checked whether a specific IAM user has a password configured for logging into the AWS Web Management Console |
| ListAccessKeys            | 29    | Display all active and inactive Access Key IDs associated with a specific IAM user                                     |
| ListAccountAliases        | 1     | Find the friendly, human-readable name (alias) of the AWS account                                                      |
| ListAttachedGroupPolicies | 1     | View all the managed IAM policies directly attached to a specific IAM group                                            |
| ListGroups                | 1     | List all the IAM groups defined within the AWS account                                                                 |
| ListGroupsForUser         | 30    | Find out exactly which IAM groups of a specific user belongs to                                                        |
| ListMFADevices            | 29    | List the Multi-Factor Authentication (MFA) devices configured for a specific IAM user                                  |
| ListPolicies              | 4     | List of all IAM policies available in the AWS account                                                                  |
| ListSigningCertificates   | 30    | List the signing certificates associated with a specific IAM user                                                      |
| ListUsers                 | 3     | List all IAM users created within the entire AWS account                                                               |

So, through `CreateUser` field, I know that at `9:59:33`, user `helpdesk.luke` create a new user called `marketing.mark` and set password at `9:59:38`. 
<p align="center">
	  <img src="./Assets/Image 10.1 - Attacker create new user.webp" alt="Attacker create new user" /> <br/>
	  <img src="./Assets/Image 10.2 - Attacker set password for new user.webp" alt="Attacker set password for new user" /> <br/>
  <em>Image 10: Attack create new user</em>
</p>

Then, at `9:59:38`, attacker add user `marketing.mark` into group `Admins`.
<p align="center">
	  <img src="./Assets/Image 11 - Attacker privilege attack.webp" alt="Attacker privilege attack" /> <br />
  <em>Image 11: Attacker privilege attack</em>
</p>

Then I use this SPL `index=* "userIdentity.userName"="marketing.mark"`. But I don't find any activities of user `marketing.mark` in the system. So maybe this account is for persistent attack.

## How did attacker get the resources

In `s3`, I check for `eventName="GetAccountPublicAccessBlock"`. With this field, attacker want to check the block access feature on the account is enable or not. 

It is 10 events and sadly, all 10 events appear `errorCode=NoSuchPublicAccessBlockConfiguration`.
<p align="center">
	  <img src="./Assets/Image 12 - Misconfiguration of security in account.webp" alt="Misconfiguration of security in account" /> <br />
  <em>Image 12: Misconfiguration of security in account</em>
</p>

This means, the account `helpdesk.luke` does not have block public access configurations. Which means, if there is any public host in the system, this account can access into it. 

At this point, I think attacker will check for any public bucket so that he can access to it. But when I check all other eventName in `s3`,I don't see any evidence prove that other bucket is public. 

Then, in switch to check in `iam`, But I also don not find anything special in here. Every API call I checked returned a null value. The only thing I can find is that user `helpdesk.luke` do not use 2-layer MFA authentication.
<p align="center">
	  <img src="./Assets/Image 13 - User luke do not user MFA authentication.webp" alt="User luke do not user MFA authentication" /> <br />
  <em>Image 13: User luke do not user MFA authentication</em>
</p>

However, based on the information I have, I can answer the questions below.

# Answer the Questions

**Q1: Knowing which user account was compromised is essential for understanding the attacker's initial entry point into the environment. What is the username of the compromised user?**

It is `helpdesk.luke`.

**Q2: We must investigate the events following the initial compromise to understand the attacker's motives. What is the timestamp for the first access to an S3 object by the attacker?**

It is `11/02/2023 - 9:55`.

**Q3: Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket?**

From the image 7, it is `Product2_CAD_Designs.dwg` from bucket `product-designs-repository31183937`.

**Q4: We've identified changes to a bucket's configuration that allowed public access, a significant security concern. What is the name of this particular S3 bucket?**

It is bucket `backup-and-restore98825501`.

**Q5: Creating a new user account is a common tactic attackers use to establish persistence in a compromised environment. What is the username of the account created by the attacker?**

It is `marketing.mark`.

**Q6: Following account creation, the attacker added the account to a specific group. What is the name of the group to which the account was added?**

It is group `Admins`.