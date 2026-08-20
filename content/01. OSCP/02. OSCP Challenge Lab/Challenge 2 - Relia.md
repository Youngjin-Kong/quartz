---
tags:
  - type/machine
  - platform/pwk-challenge
  - status/unsolved
  - tech/win/dll-hijack
  - tech/win/scheduled-task
  - tech/web/lfi-rfi
  - tech/pivot/chisel
type: machine
platform: pwk-challenge
ip: 192.168.243.250
cves: [CVE-2021-41773]
status: unsolved
tech_count: 4
---
About this lab

Embark on a dynamic multi-network challenge focused on identifying and exploiting vulnerabilities in a diverse range of systems. From leveraging directory traversal (CVE-2021-41773) and privilege escalation to service hijacking, this lab provides a hands-on approach to pivoting through internal networks, cracking credentials, and achieving complete domain compromise while showcasing advanced lateral movement techniques.

  

Lab Description

Dive into a complex, multi-network environment where you'll uncover and exploit a variety of vulnerabilities across interconnected systems. Starting with CVE-2021-41773, a directory traversal vulnerability in Apache, you’ll gain initial access to WEB01 and escalate privileges to harvest sensitive credentials. Progress through internal networks using pivoting techniques and tunneling tools like Chisel, overcoming layered defenses and limited visibility. Identify and exploit misconfigurations such as DLL hijacking and scheduled task abuse to gain deeper access, eventually harvesting and cracking credentials to fully compromise the domain and seize administrative control.

  

Learning Objectives

After completing this lab, learners will be able to:

Exploit the Apache Path Traversal vulnerability (CVE-2021-41773) to gain initial access to the WEB01 machine.

Perform privilege escalation on compromised systems to extract sensitive credentials for lateral movement.

Utilize pivoting techniques and tunneling tools like Chisel to access internal network resources.

Identify and exploit service misconfigurations, such as DLL hijacking or scheduled tasks, to escalate privileges.

Harvest and crack credentials to gain administrative control over domain systems and complete the domain takeover.




Objectives

We are tasked with a penetration test of _Relia_, an industrial company building driving systems for the timber industry. The target got attacked a few weeks ago and wants now to get an assessment of their IT security. Their goal is to determine if an attacker can breach the perimeter and get access to the domain controller in the internal network.

The organization topology diagram is shown below and the public subnet network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.

![Figure 1: Challenge Scenario](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR-LABS/imgs/challengelab2/01233ad451c1561bc376ad96effdf101-CL2Topo4px.png)

Figure 1: Challenge Scenario




# 192.168.243.250

`offsec/lab`


