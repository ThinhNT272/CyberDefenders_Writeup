# Scenario & Objective

After Karen started working for 'TAAUSAI,' she began doing illegal activities inside the company. 'TAAUSAI' hired you as a soc analyst to kick off an investigation on this case.

You acquired a disk image and found that Karen uses Linux OS on her machine. Analyze the disk image of Karen's computer and answer the provided questions.

- **Category**: Endpoint Forensics
- **Tools**: FTK Imager

# Answer the Questions

**Q1: Which Linux distribution is being used on this machine?**

From the `boot` folder, I know karen use `kali linux` 4.13.0 version. 
<p align="center">
  <img src="./Assets/Image 1 - Boot OS.webp" alt="Boot OS" /> <br />
  <em>Image 1: Boot OS</em>
</p>

**Q2: What is the MD5 hash of the Apache access.log file?**

Go to `/var/log/apache2/`, right click to `access.log` and choose `Export File Hash List...`. Then open the file and we have hash information of this file.
<p align="center">
  <img src="./Assets/Image 2 - Hash value of apache access log.webp" alt="Hash value of apache access log" /> <br />
  <em>Image 2: Hash value of apache access log</em>
</p>

So the MD5 hash value of file is: `d41d8cd98f00b204e9800998ecf8427e`.

**Q3: It is suspected that a credential dumping tool was downloaded. What is the name of the downloaded file?**

From `root/Downloads` folder, I know the downloaded file is `mimikatz_trunk.zip`.
<p align="center">
  <img src="./Assets/Image 3 - Name of downloaded file.webp" alt="Name of downloaded file" /> <br />
  <em>Image 3: Name of downloaded file</em>
</p>

**Q4: A super-secret file was created. What is the absolute path to this file?**

To determine the absolute path of the super-secret file, we need to investigate user activity logs stored on the system. One of the most valuable sources for such analysis in Linux systems is the `.bash_history` file
<p align="center">
  <img src="./Assets/Image 4 - Bash history.webp" alt="Bash history" /> <br />
  <em>Image 4: Bash history</em>
</p>

So, the answer is `/root/Desktop/SuperSecretFile.txt`.

**Q5: What program used the file didyouthinkwedmakeiteasy.jpg during its execution?**

Still from the `.bash_history` file above, I find this information.
<p align="center">
  <img src="./Assets/Image 5 - Program execute file.jpg.webp" alt="Program execute file.jpg" /> <br />
  <em>Image 5: Program execute file.jpg</em>
</p>

So, the answer is `binwalk`. This is a forensic tool designed for analyzing binary files and firmware images. It is widely used to extract embedded files, hidden data, and compressed archives within a binary structure.

**Q6: What is the third goal from the checklist Karen created?**

After researching, I found the `checklist` file in `/root/Desktop` folder.
<p align="center">
  <img src="./Assets/Image 6 - Checklist file.webp" alt="Checklist file" /> <br />
  <em>Image 6: Checklist file</em>
</p>

So, the third goal of Karen is `profit`.

**Q7: How many times was Apache run?**

To know how many times was apache run, I need to see logs to determine it. Go to `/var/log/apache2/access.log` 
<p align="center">
  <img src="./Assets/Image 7 - Access log of apache2.webp" alt="Access log of apache2" /> <br />
  <em>Image 7: Access log of apache2</em>
</p>

There is nothing appear, so the answer is `0`.

**Q8: This machine was used to launch an attack on another. Which file contains the evidence for this?**

To have evidence of Karen attacked on another computer, I check for log file. But I cannot find anything prove it, even in `.bash_history` file. So I scroll down and just simple check every file appear and in the `irZLAohL.jpeg` image, I found Karen run a program through cmd.
<p align="center">
  <img src="./Assets/Image 8 - Karen attackers another computer.webp" alt="Karen attackers another computer" /> <br />
  <em>Image 8: Karen attackers another computer</em>
</p>

So, Karen ran file `anylnao.exe` in `C:\Users\Bob\AppData\Local\Temp\` folder of Bob computer.

**Q9: It is believed that Karen was taunting a fellow computer expert through a bash script within the Documents directory. Who was the expert that Karen was taunting?**

Follow the task, I check all file exist in `Documents` directory. Then I found this in `/root/Documents/myfirsthack/firstscript_fixed` file.
<p align="center">
  <img src="./Assets/Image 9 - Karen taunted Young expert.webp" alt="Karen taunted Young expert" /> <br />
  <em>Image 9: Karen taunted Young expert</em>
</p>

So Karen taunted `Young` expert.

**Q10: A user executed the su command to gain root access multiple times at 11:26. Who was the user?**

Follow the task, I check for every log that have timestamp. 
<p align="center">
  <img src="./Assets/Image 10 - Karen executed su command to user.webp" alt="Karen executed su command to user" /> <br />
  <em>Image 10: Karen executed su command to user</em>
</p>

Then, in the `auth.log` file in `/root/log` folder, I found the information, Karen used `su` command for user `postgres`.

**Q11: Based on the bash history, what is the current working directory?**

As the task, I go to `/root/.bash_history` file and find a command `cd` below.
<p align="center">
  <img src="./Assets/Image 11 - Current working folder.webp" alt="Current working folder" /> <br />
  <em>Image 11: Current working folder</em>
</p>

But the full cd is not longer than answer format. Only folder `/root/Documents/myfirsthack` matches answer format.