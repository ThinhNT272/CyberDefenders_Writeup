# Scenario & Objective

We're currently in the midst of a murder investigation, and we've obtained the victim's phone as a key piece of evidence. After conducting interviews with witnesses and those in the victim's inner circle, your objective is to meticulously analyze the information we've gathered and diligently trace the evidence to piece together the sequence of events leading up to the incident.

- **Category**: Endpoint Forensics
- **Tools**: ALEAPP, DB Browser for SQLite
## Overview

The victim, whose identity is tied to the contacts and accounts on his Android phone, was deeply involved in online trading through the **Olymp Trade** application. His trading addiction led him to invest all of his money and debt - owing **250,000 EGP** to an individual named **Shady Wahab**.

On **September 20, 2023**, the victim quietly left his residence without informing anyone. Location data from Google Maps on his phone revealed that he traveled to **The Nile Ritz-Carlton** hotel in Cairo, where he had reserved a room for 10 days. He also had a flight booked from Cairo to **Las Vegas**, with a cached boarding pass found in the phone's image manager.

Discord chat logs further revealed that the victim had arranged to meet a friend at **The Mob Museum** in Las Vegas.
# Analysis

**Q1: Based on the accounts of the witnesses and individuals close to the victim, it has become clear that the victim was interested in trading. This has led him to invest all of his money and acquire debt. Can you identify the `SHA256` of the trading application the victim primarily used on his phone?**

After using ALEAPP to analyze the Android log folder, I got a report. Going to the Installed Apps category, I found that the victim used `olymptrade` for trading, and it also shows the SHA256 hash of the application.
<p align="center">
  <img src="./Assets/Image 1 - Trading app.webp" alt="Trading app" /><br>
  <em>Image 1: Trading app</em>
</p>

**Q2: According to the testimony of the victim's best friend, he said, "`While we were together, my friend got several calls he avoided. He said he owed the caller a lot of money but couldn't repay now`". How much does the victim owe this person?**

From the Call Logs category, I can see that the victim avoided calls from `+201172137258`.
<p align="center">
  <img src="./Assets/Image 2 - The victim's creditor.webp" alt="The victim's creditor" /><br>
  <em>Image 2: The victim's creditor</em>
</p>

And from the "SMS & MMS" category, I found that the victim owes the caller about `250,000 EGP`.
<p align="center">
  <img src="./Assets/Image 3 - The victim's creditor SMS.webp" alt="The victim's creditor SMS" /><br>
  <em>Image 3: The victim's creditor SMS</em>
</p>

**Q3: What is the name of the person to whom the victim owes money?**

From the "Contacts" category, I identified the victim's creditor as `Shady Wahab`.
<p align="center">
  <img src="./Assets/Image 4 - Name of victim's creditor.webp" alt="Name of victim's creditor" /><br>
  <em>Image 4: Name of victim's creditor</em>
</p>

**Q4: Based on the statement from the victim's family, they said that on `September 20, 2023`, he departed from his residence without informing anyone of his destination. Where was the victim located at that moment?**

To know where the victim located at that moment, I need some information like GPS, something like that. So, I check all the category, through all the pages and I found this information at Recent Activity category.
<p align="center">
  <img src="./Assets/Image 5 - Google map information.webp" alt="Google map information" /><br>
  <em>Image 5: Google map information</em>
</p>

So, the victim used google map on that day. There also has a snapshot image below show that the victim is in `The Nile Ritz-Carlton`.

**Q5: The detective continued his investigation by questioning the hotel lobby. She informed him that the victim had reserved the room for 10 days and had a flight scheduled thereafter. The investigator believes that the victim may have stored his ticket information on his phone. Look for where the victim intended to travel.**

The victim stored the ticket in the Image Manager Cache category, which shows that the victim had a flight scheduled from Cairo to `Las Vegas`.
<p align="center">
  <img src="./Assets/Image 6 - Flight ticket.webp" alt="Flight ticket" /><br>
  <em>Image 6: Flight ticket</em>
</p>

**Q6: After examining the victim's Discord conversations, we discovered he had arranged to meet a friend at a specific location. Can you determine where this meeting was supposed to occur?**

At the Discord Chats category, the victim friend with user name rob1ns0n wanted to meet the victim at `The Mob Museum`.
<p align="center">
  <img src="./Assets/Image 7 - Meeting destination.webp" alt="Meeting destination" /><br>
  <em>Image 7: Meeting destination</em>
</p>
