+++
title = 'E-Mail Security For IT Dummies'
date = 2024-05-21T12:00:00Z
draft = false
+++

## What is E-mail Security ?

Since Normies in the IT space are encountering email more and more these days and they are encountering issues, I wanted to create a blog post that explains Email Security in a human way, so that not every issue is redirected to IT Security but people can determine themselves what is wrong and "how" to solve it.

Let's start with the beginning. E-Mail Security all starts with SPF, DKIM and DMARC:

- **SPF (Sender Policy Framework)**
- **DKIM (DomainKeys Identified Mail)**
- **DMARC (Domain-Based Message Authentication, Reporting & Conformance)**

These three technologies work together to protect against email spoofing and tampering. Essentially, SPF and DKIM are two separate control mechanisms that help secure emails while DMARC acts as a policy layer on top of these two, instructing the receiving email server on how to handle emails that fail SPF or DKIM checks.

---

## SPF

**Sender Policy Framework** is a control mechanism that allows us to determine whether the sender's address is authorized to send on behalf of the domain.

### In Human Terms

One way to explain SPF as a metaphor can be through the example of traditional post. Imagine a small village with a post office, where people can send letters. The SPF can be seen as a register or a list that collects the names of all the people who live in the village and are allowed to send letters using the village's post box.

When someone wants to send a letter, they write it, put it in an envelope, and write the destination address on the front and the sender's name and address on the back. The post office then checks the sender's name against the SPF register to make sure that the person is authorized to send letters from the village's post box. If the sender's name is not on the SPF register, or if the letter does not have a sender's name, the letter is discarded and not sent.

The receiving mail server will check these records upon receiving an email and will find this domain by looking at the MAIL FROM attribute or Return-Path attribute. If the sender's IP address is incorrect, the SPF check will be invalid.

### For the Techies

SPF is configured and checked using DNS TXT records. A typical record looks like the following:

```
v=spf1 mx include:my.company.com include:spf.protection.outlook.com ip4:1.2.3.4 -all
```

- `v=spf1` SPF Version 1
- `mx` include all mail servers mentioned in MX records of the domain are allowed to send emails on behalf of this domain
- `include:my.company.com` Accept all things mentioned by the subdomain `my` for the domain `company.com`
- `include:spf.protection.outlook.com` typical SPF record to allow O365 to send emails on behalf of the company
- `ip4:1.2.3.4` the IP address: 1.2.3.4 is also authorized to send emails from this domain
- `-all` all other emails are not to be accepted

Since this is a normal DNS TXT record we can check this information ourselves for companies. For example:

```powershell
PS C:\Users\User> nslookup -type=txt
Default Server:  localhost
Address:  127.0.0.1
> my.company.com
Server:  localhost
Address:  127.0.0.1
Non-authoritative answer:
my.company.com  text =
    "v=spf1 include:emailsrvr.com ~all"
my.company.com  text =
    "v=spf1 mx a ip4:74.122.238.0/27 -all"
```

How is this used in the real process? When a receiving mail server receives an email, it will check the SPF record and verify if it corresponds to the headers it can see in the email itself. If it does not check, the SPF check will have failed.

---

## DKIM

**DomainKeys Identified Mail** is a control mechanism that allows us to determine whether an email has been tampered with on its way to the recipient's end.

### In Simple Terms

This is comparable with the wax seals technique used in the middle ages. When a king wanted to send a confidential letter to another person in the realm, he would write, fold and put the letter in an envelope and then seal this with hot wax. Before the wax cools, he would press a unique seal (a stamp with his ring) into it. The seal serves two purposes:

1. **Authentication:** recipients know the letter is coming from the king because only he has this unique ring that could make this seal.
2. **Integrity:** as long as the wax seal is intact upon arrival, it's obvious the letter has not been tampered with.

The person receiving this letter would inspect the wax seal to make sure authenticity and integrity of the letter are intact and present before they will trust the letter.

So back to sending digital letters. When you send an email, your mail server uses DKIM to attach a digital signature to the email's header. This signature is created by hashing the email and then encrypting this hash with the private DKIM key. This process ensures integrity and authenticity of the email.

Upon receiving an email, the recipient's mail server retrieves the sender's public DKIM key through a DNS request. Using this public key, the recipient's mail server decrypts the DKIM signature found in the email's header, the result of this should be a hash. The server then hashes the received email again (excluding the DKIM-Signature header obviously) and compares this new hash to the result of the previous step. If the two hashes match, the email is verified as authentic and untampered.

### For The Techies

This public DKIM key can be retrieved using a DNS request to `<selector>._domainkey.domain.tld`:

```powershell
PS C:\Users\User> nslookup -type=txt
Default Server:  UnKnown
Address:  127.0.0.1
> google._domainkey.company.com
Server:  UnKnown
Address:  127.0.0.1
Non-authoritative answer:
google._domainkey.company.com
> default._domainkey.company.com
Server:  UnKnown
Address:  192.168.1.80
Non-authoritative answer:
    default._domainkey.company.com  text =
        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGT4S25STu+UCISNokNtvo7xsQUGmoA6Fwe6RmH7gd9po6F52Hp83Fvoh405wgU1WBWtZ5TsxLZt9aFJOKADGF1czLlGDspSl/9vLWj1gW3Y/zy//KLIa9KkKBBBMmm9xnm6AWiWisxVs4dLZyq9yPOH7hRkkRt9025aYdYluFWwIDAQAB"
        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUVY8ab2ZVJSHfLXQVnoGXSVff8VY+5Xh96m27FNYQk+r6ZYdZF8RF9L1tUH9JsZelCQQblITo8BEzO5BuZ941/oar8xceK1UN0Lpuf4cIHpnhdJbpL+3g8exUBn26OjXDG61lLHaZtqSlqrBNo26/LmpY/WaJhZ9sMVNgU27W6wIDAQAB"
```

- `v=DKIM1` DKIM Version 1
- `k=rsa` encryption algorithm = rsa
- `p=...` encryption key

---

## DMARC

**Domain-based Message Authentication, Reporting & Conformance (DMARC)** is the overarching policy mechanism that instructs the receiving mail server on how to handle emails that fail SPF or DKIM checks. It will tell the receiving mail server if it needs to enforce the SPF/DKIM records when something is wrong or to let non-compliant mails right through.

### In Simple Terms

DMARC is like the village council's policy on handling questionable letters. If a letter fails the SPF or DKIM checks (like not being on the authorized sender list or having a broken seal), DMARC dictates whether the letter should be rejected, quarantined, or accepted. Additionally, DMARC can instruct the mail server to report such incidents back to the sender's domain for further analysis.

### For the Techies

DMARC policies are also configured via DNS TXT records. A typical DMARC record might look like this:

```powershell
PS C:\Users\User> nslookup -type=txt
Default Server:  localhost
Address:  127.0.0.1
> _dmarc.company.com
Server:  localhost
Address:  127.0.0.1
Non-authoritative answer:
    _dmarc.company.com  text =
        "v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com; ruf=mailto:dmarc-failure@company.com;"
```

- `v=DMARC1` DMARC version 1
- `p=reject` Policy is to reject emails that fail SPF/DKIM
- `rua=mailto:dmarc-reports@company.com` Aggregate reports email address
- `ruf=mailto:dmarc-failure@company.com` Forensic reports email address

#### How DMARC works

1. **Policy Application:** The receiving mail server applies the DMARC policy based on the results of the SPF and DKIM checks.
2. **Reporting:** DMARC can send reports back to the domain owner, providing information about emails that fail authentication checks. This helps in monitoring and adjusting email policies.

By implementing DMARC, organizations can significantly reduce the chances of email spoofing and ensure that their emails are properly authenticated. This builds trust in the email ecosystem and protects both senders and recipients from phishing and other email-based attacks. 
