+++
title = 'The Security Maturity Grind in 2025'
date = 2024-05-23T12:00:00Z
description = "Level up your security maturity using open source tools"
tags = ["rant", "CyberSecurity", "opensource", "pingcastle", "Bloodhound", "LockSmith", "Maester"]
draft = false
+++


## Security is an arms race
In the world of Cyber Security, we are always one step behind as defenders, and this makes total sense. In the past I've learned you have 2 kinds of people, ones that will do first, think later and then do again or the ones that think first, then do and then think again. In both cases there is a reflective moment. 
In a perfect world, where no crime nor malicious intent exists, we wouldn't need security. 
Let's look at this from another perspective.

## brief history of IT yesterday and tomorrow
The automotive industry is a nice comparison to make. When the first cars were released, they didn't have seatbelts, ABS, lane assist, parking sensors, etc. and it wasn't "needed". There were no regulations around drinking and driving, speeding, or even a driving license. Project this in today's world and it's completely crazy. Yes, we have updated the rules because we have more cars on the road and the cars can go faster and are a more vital part of life whereas before it was more of a luxurious item to have. 
Same goes for the internet.

In the first days of the internet there were no rules, and it was not "needed". Our lives weren't so dependent on this new technology yet. Corporate businesses could still function without and continuity was guaranteed even without the internet or computers.

Fast forward to 2025. The world is completely different and we have shifted to a more digital lifestyle. You cannot imagine a way of living without smart phones, google and nowadays even AI chatbots like ChatGPT. But more importantly, businesses don't function anymore without IT. The very old generation can maybe still uphold operative processes when IT fails for a few hours, but most employees are clueless. Even in non-IT sectors. This brings a whole set of risks with us and a whole set of new rules needs to be made. For this reason, laws like GDPR and NIS2 are put in place and made mandatory for companies that deliver critical services to the public, nation or worldwide. 
But. There is a giant but here. 
First, the companies that are deemed critical for the nation's infrastructure are usually companies that have been critical for a long time and therefore implicitly been here for a long time. You can see where I'm going here, their IT landscape is also old. meaning that there is probably lots of old infrastructure and legacy applications. It's this old IT landscape that makes it difficult to level up your security posture, to even start getting compliant to NIS2 and GDPR. 
Secondly, what kind of checks are we doing to see if a company is compliant with the rules or not? Are we just checking the checkbox superficially? 
And finally, when a company has been found compliant and earns the badge, how much time goes by before it gets audited again? Are we doing this exercise just once and then letting it rest for a few years before we check again? Are we not doing this continuously? Would it be possible to do so?

It all starts with governance and getting a grip on the infrastructure. Besides all the processes and policies that are foundational to this, let's take a deeper look into a secure infrastructure, good IT hygiene and a way to baseline and monitor the state continuously.

## The best gamekeeper used to be a poacher.
To maintain good security, we need to become the thing we are defending ourselves from, hackers. By trying to find weaknesses in environments the way attackers do, we can find the weaknesses they would likely exploit to achieve total domain compromise. 
This is a good start for companies just starting out their security departments but also a good idea for companies that have been doing security for a long time. 
Some good tools are:

* PingCastle
* Bloodhound
* Locksmith
* Measter

---

## Tools Explained

### PingCastle
Pingcastle is a tool founded by Vincent Letoux, bought and maintained by Netwrix since 2024 and has been used by so many companies to check the risk level of their AD. it enumerates a lot of Active Directory and is basically a configuration compliancy checker against some recommendations from Microsoft and other standards. It's super simple to run, you just need an AD connected server and administrator permissions on here.
In terms of AD permissions, an AD user with read permissions is enough.
It will look for stale objects, privileged accounts, trusts and other anomalies in the environment and comes up with a risk score of 100. 100 being high risk and 0 being low risk. you will want to get your AD into a state of <10 / 100. Once you are there it is recommended to run Pingcastle on a frequent basis and use it as a baseline for your security posture.

### Bloodhound
Bloodhound is another open-source tool focusing on Active Directory (And Azure Active Directory) but more focused on path analysis. It will enumerate all the objects in AD and look for Dangerous persmissions by certain identities, if there is an obvious path from a normal unprivileged user to a Domain Administrator, Bloodhound is the tool to find it. Run it and check for obvious paths, if you're not paying for an enterprise license it is recommended to use some github scripts on top of this database to find the paths quickly.

### Locksmith
ADCS, or Active Directory Certificate Services have been around for a long time but only found vulnerable since a few years. it's in use for almost all companies and it's a kind of thing that once it's been set up and it's working, it gets forgotten. Also, lots of guides on how to set up these things are not with security in mind. even the official guides for some products are telling you to configure the certificates in vulnerable states. 
Run the Locksmith tool right now in Mode 1, you will see all your certificate templates and you will see that some of them are vulnerable. try to get it to zero and when that's done. you can now run this tool once in a while but most importantly, when new certificates templates are being created.

### Maester
This one focuses on the cloud rather than the other 3 focusing on premise environments. It's very new but let's be honest, the cloud is pretty new as well. we are still developing most of it and so security is still being created too. Maester.dev is a good way to start. It is a powershell framework built upon the Pester framework and you can create your own tests for your own environment. It is up to you to identify your crown jewels and write some tests for it. But surely you can start with the out of the box tests to get some basics right. 
Same as with Locksmith and Pingcastle, just work down the list and complete as many items as possible.

### Combining the tools in a open-source Framework
Automating and combining reports from these tools can result in a comprehensive way to safeguard the security posture of your infrastructure. My goal is to create this framework.

TBC.
