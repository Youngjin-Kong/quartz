## 192.168.218.95

### credentials
`Eric.Wallows/EricLikesRunning800`

### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Secura/95]
└─$ nnmap 192.168.218.95
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-14 09:52 +0900
Warning: 192.168.218.95 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.218.95
Host is up (0.087s latency).
Not shown: 65504 closed tcp ports (reset)
PORT      STATE    SERVICE         VERSION
135/tcp   open     msrpc           Microsoft Windows RPC
139/tcp   open     netbios-ssn     Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?
3389/tcp  open     ms-wbt-server   Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: SECURA
|   NetBIOS_Domain_Name: SECURA
|   NetBIOS_Computer_Name: SECURE
|   DNS_Domain_Name: secura.yzx
|   DNS_Computer_Name: secure.secura.yzx
|   DNS_Tree_Name: secura.yzx
|   Product_Version: 10.0.19041
|_  System_Time: 2026-08-14T00:55:39+00:00
|_ssl-date: 2026-08-14T00:57:02+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=secure.secura.yzx
| Not valid before: 2026-08-13T00:45:20
|_Not valid after:  2027-02-12T00:45:20
5001/tcp  open     commplex-link?
| fingerprint-strings:
|   SIPOptions:
|     HTTP/1.1 200 OK
|     Content-Type: text/html; charset=ISO-8859-1
|     Content-Length: 132
|_    MAINSERVER_RESPONSE:<serverinfo method="setserverinfo" mainserver="5001" webserver="44444" pxyname="192.168.45.169" startpage=""/>
5040/tcp  open     unknown
5985/tcp  open     http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open     ssl/wsmans?
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
| Not valid before: 2026-08-13T00:47:15
|_Not valid after:  2036-08-11T00:47:15
|_ssl-date: 2026-08-14T00:57:02+00:00; 0s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
7680/tcp  open     pando-pub?
8443/tcp  open     ssl/https-alt   AppManager
| ssl-cert: Subject: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
| Not valid before: 2019-02-27T11:03:03
|_Not valid after:  2050-02-27T11:03:03
|_ssl-date: 2026-08-14T00:57:02+00:00; 0s from scanner time.
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404
|     Set-Cookie: JSESSIONID_APM_44444=262CF57D979186A7F7EB0D00282DBE37; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 973
|     Date: Fri, 14 Aug 2026 00:52:56 GMT
|     Connection: close
|     Server: AppManager
|     <!DOCTYPE html>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     <!-- Includes commonstyle CSS and dynamic style sheet bases on user selection -->
|     <link href="/images/commonstyle.css?rev=14440" rel="stylesheet" type="text/css">
|     <link href="/images/newUI/newCommonstyle.css?rev=14260" rel="stylesheet" type="text/css">
|     <link href="/images/Grey/style.css?rev=14030" rel="stylesheet" type="text/css">
|     <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body bgcolor="#FFFFFF" leftmarg
|   GetRequest:
|     HTTP/1.1 200
|     Set-Cookie: JSESSIONID_APM_44444=7BF655BED9F2C21D0CA76A42155782C3; Path=/; Secure; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Fri, 14 Aug 2026 00:52:55 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 403
|     Set-Cookie: JSESSIONID_APM_44444=39E061B9B763E62CB69923ED6812F5B3; Path=/; Secure; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Fri, 14 Aug 2026 00:52:55 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|_    margin: 0; color:#000;
|_http-server-header: AppManager
|_http-title: Site doesn''t have a title (text/html).
12000/tcp open     cce4x?
20832/tcp filtered unknown
44444/tcp open     cognex-dataman?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Set-Cookie: JSESSIONID_APM_44444=F0E9A2F07674119CDF0A5CE182546884; Path=/; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Fri, 14 Aug 2026 00:52:55 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 403
|     Set-Cookie: JSESSIONID_APM_44444=B3E6A79A01D0E7733EA1B074003CECED; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Fri, 14 Aug 2026 00:52:55 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|     margin: 0; color:#000;
|     font-
|   RTSPRequest:
|     HTTP/1.1 505
|     vary: accept-encoding
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 2142
|     Date: Fri, 14 Aug 2026 00:52:55 GMT
|     Server: AppManager
|     <!doctype html><html lang="en"><head><title>HTTP Status 505
|_    HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#
47001/tcp open     http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc           Microsoft Windows RPC
49665/tcp open     msrpc           Microsoft Windows RPC
49666/tcp open     msrpc           Microsoft Windows RPC
49667/tcp open     msrpc           Microsoft Windows RPC
49668/tcp open     msrpc           Microsoft Windows RPC
49669/tcp open     msrpc           Microsoft Windows RPC
49670/tcp open     msrpc           Microsoft Windows RPC
49671/tcp open     msrpc           Microsoft Windows RPC
49672/tcp open     msrpc           Microsoft Windows RPC
49675/tcp open     tcpwrapped
49698/tcp open     java-rmi        Java RMI
49751/tcp open     unknown
52155/tcp filtered unknown
56902/tcp filtered unknown
58635/tcp filtered unknown
60187/tcp open     unknown
| fingerprint-strings:
|   X11Probe:
|_    CLOSE_SESSION
60188/tcp open     unknown
| fingerprint-strings:
|   SMBProgNeg, X11Probe:
|_    CLOSE_SESSION
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5001-TCP:V=7.98%I=7%D=8/14%Time=6A7E6745%P=x86_64-pc-linux-gnu%r(SI
SF:POptions,DB,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html;\x20c
SF:harset=ISO-8859-1\r\nContent-Length:\x20132\r\n\r\nMAINSERVER_RESPONSE:
SF:<serverinfo\x20method=\"setserverinfo\"\x20mainserver=\"5001\"\x20webse
SF:rver=\"44444\"\x20pxyname=\"192\.168\.45\.169\"\x20startpage=\"\"/>\n\0
SF:\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.98%T=SSL%I=7%D=8/14%Time=6A7E66E8%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,24E,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONID_A
SF:PM_44444=7BF655BED9F2C21D0CA76A42155782C3;\x20Path=/;\x20Secure;\x20Htt
SF:pOnly\r\nAccept-Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"\r\
SF:nLast-Modified:\x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nCont
SF:ent-Type:\x20text/html\r\nContent-Length:\x20261\r\nDate:\x20Fri,\x2014
SF:\x20Aug\x202026\x2000:52:55\x20GMT\r\nConnection:\x20close\r\nServer:\x
SF:20AppManager\r\n\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBLIC\
SF:x20\"-//W3C//DTD\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<head
SF:>\n<!--\x20This\x20comment\x20is\x20for\x20Instant\x20Gratification\x20
SF:to\x20work\x20applications\.do\x20-->\n<script>\n\n\twindow\.open\(\"/w
SF:ebclient/common/jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</head>
SF:\n</html>\n")%r(HTTPOptions,849,"HTTP/1\.1\x20403\x20\r\nSet-Cookie:\x2
SF:0JSESSIONID_APM_44444=39E061B9B763E62CB69923ED6812F5B3;\x20Path=/;\x20S
SF:ecure;\x20HttpOnly\r\nCache-Control:\x20private\r\nExpires:\x20Thu,\x20
SF:01\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;char
SF:set=UTF-8\r\nContent-Length:\x201810\r\nDate:\x20Fri,\x2014\x20Aug\x202
SF:026\x2000:52:55\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager
SF:\r\n\r\n<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">
SF:\n<meta\x20http-equiv=\"Content-Type\"\x20content=\"UTF-8\">\n<!--\$Id\
SF:$-->\n\n\n\n\n\n\n\n\n\n<html>\n<head>\n<title>Applications\x20Manager<
SF:/title>\n\n<link\x20REL=\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">
SF:\n\n</head>\n\n<body\x20style=\"background-color:#fff;\">\n\n<style\x20
SF:type=\"text/css\">\n\t#container-error\n\t{\n\t\tborder:1px\x20solid\x2
SF:0#c1c1c1;\n\t\tbackground:\x20#fff;\x20font:11px\x20Arial,\x20Helvetica
SF:,\x20sans-serif;\x20width:90%;\x20margin:80px;\n\t\x20\t\n\t}\n\n\t#hea
SF:der-error\n\t{\n\t\tbackground:\x20#ededed;\x20line-height:18px;\n\t\tp
SF:adding:\x2015px;\x20color:#000;\x20font-size:8px;\n\t}\n\n\t#header-err
SF:or\x20h1\n\t{\n\t\tmargin:\x200;\x20\x20color:#000;")%r(FourOhFourReque
SF:st,4C3,"HTTP/1\.1\x20404\x20\r\nSet-Cookie:\x20JSESSIONID_APM_44444=262
SF:CF57D979186A7F7EB0D00282DBE37;\x20Path=/;\x20Secure;\x20HttpOnly\r\nCon
SF:tent-Type:\x20text/html;charset=UTF-8\r\nContent-Length:\x20973\r\nDate
SF::\x20Fri,\x2014\x20Aug\x202026\x2000:52:56\x20GMT\r\nConnection:\x20clo
SF:se\r\nServer:\x20AppManager\r\n\r\n<!DOCTYPE\x20html>\n\n<meta\x20http-
SF:equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n\n\n\n\n\n\n\n\n\n\n
SF:<html>\n<head>\n<title>Applications\x20Manager</title>\n\n<link\x20REL=
SF:\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">\n\n<!--\x20Includes\x20
SF:commonstyle\x20CSS\x20and\x20dynamic\x20style\x20sheet\x20bases\x20on\x
SF:20user\x20selection\x20-->\n\n<link\x20href=\"/images/commonstyle\.css\
SF:?rev=14440\"\x20rel=\"stylesheet\"\x20type=\"text/css\">\n\n\x20\x20\x2
SF:0\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20href=
SF:\"/images/newUI/newCommonstyle\.css\?rev=14260\"\x20rel=\"stylesheet\"\
SF:x20type=\"text/css\">\n\x20\x20\x20\x20\n\n<link\x20href=\"/images/Grey
SF:/style\.css\?rev=14030\"\x20rel=\"stylesheet\"\x20type=\"text/css\">\n\
SF:n<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;\x20charse
SF:t=iso-8859-1\">\n</head>\n\n<body\x20bgcolor=\"#FFFFFF\"\x20leftmarg");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44444-TCP:V=7.98%I=7%D=8/14%Time=6A7E66E7%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,246,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONID_APM_44
SF:444=F0E9A2F07674119CDF0A5CE182546884;\x20Path=/;\x20HttpOnly\r\nAccept-
SF:Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"\r\nLast-Modified:\
SF:x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nContent-Type:\x20tex
SF:t/html\r\nContent-Length:\x20261\r\nDate:\x20Fri,\x2014\x20Aug\x202026\
SF:x2000:52:55\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager\r\n
SF:\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD
SF:\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<head>\n<!--\x20This\
SF:x20comment\x20is\x20for\x20Instant\x20Gratification\x20to\x20work\x20ap
SF:plications\.do\x20-->\n<script>\n\n\twindow\.open\(\"/webclient/common/
SF:jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</head>\n</html>\n")%r(
SF:HTTPOptions,841,"HTTP/1\.1\x20403\x20\r\nSet-Cookie:\x20JSESSIONID_APM_
SF:44444=B3E6A79A01D0E7733EA1B074003CECED;\x20Path=/;\x20HttpOnly\r\nCache
SF:-Control:\x20private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:
SF:00\x20GMT\r\nContent-Type:\x20text/html;charset=UTF-8\r\nContent-Length
SF::\x201810\r\nDate:\x20Fri,\x2014\x20Aug\x202026\x2000:52:55\x20GMT\r\nC
SF:onnection:\x20close\r\nServer:\x20AppManager\r\n\r\n<meta\x20http-equiv
SF:=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"UTF-8\">\n<!--\$Id\$-->\n\n\n\n\n\n\n\n\n\n<ht
SF:ml>\n<head>\n<title>Applications\x20Manager</title>\n\n<link\x20REL=\"S
SF:HORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">\n\n</head>\n\n<body\x20sty
SF:le=\"background-color:#fff;\">\n\n<style\x20type=\"text/css\">\n\t#cont
SF:ainer-error\n\t{\n\t\tborder:1px\x20solid\x20#c1c1c1;\n\t\tbackground:\
SF:x20#fff;\x20font:11px\x20Arial,\x20Helvetica,\x20sans-serif;\x20width:9
SF:0%;\x20margin:80px;\n\t\x20\t\n\t}\n\n\t#header-error\n\t{\n\t\tbackgro
SF:und:\x20#ededed;\x20line-height:18px;\n\t\tpadding:\x2015px;\x20color:#
SF:000;\x20font-size:8px;\n\t}\n\n\t#header-error\x20h1\n\t{\n\t\tmargin:\
SF:x200;\x20\x20color:#000;\n\t\tfont-")%r(RTSPRequest,912,"HTTP/1\.1\x205
SF:05\x20\r\nvary:\x20accept-encoding\r\nContent-Type:\x20text/html;charse
SF:t=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x202142\r\nDate:\
SF:x20Fri,\x2014\x20Aug\x202026\x2000:52:55\x20GMT\r\nServer:\x20AppManage
SF:r\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20St
SF:atus\x20505\x20\xe2\x80\x93\x20HTTP\x20Version\x20Not\x20Supported</tit
SF:le><style\x20type=\"text/css\">h1\x20{font-family:Tahoma,Arial,sans-ser
SF:if;color:white;background-color:#525D76;font-size:22px;}\x20h2\x20{font
SF:-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;fo
SF:nt-size:16px;}\x20h3\x20{font-family:Tahoma,Arial,sans-serif;color:whit
SF:e;background-color:#525D76;font-size:14px;}\x20body\x20{font-family:Tah
SF:oma,Arial,sans-serif;color:black;background-color:white;}\x20b\x20{font
SF:-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;}\
SF:x20p\x20{font-family:Tahoma,Arial,sans-serif;background:white;color:bla
SF:ck;font-size:12px;}\x20a\x20{color:black;}\x20a\.name\x20{color:black;}
SF:\x20\.line\x20{height:1px;background-color:#");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port60187-TCP:V=7.98%I=7%D=8/14%Time=6A7E6728%P=x86_64-pc-linux-gnu%r(X
SF:11Probe,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port60188-TCP:V=7.98%I=7%D=8/14%Time=6A7E6727%P=x86_64-pc-linux-gnu%r(S
SF:MBProgNeg,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(X11Probe,1
SF:A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/14%OT=135%CT=1%CU=40923%PV=Y%DS=4%DC=T%G=Y%TM=6A7E67
OS:DF%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=107%TI=I%CI=I%TS=U)SEQ(SP=
OS:102%GCD=1%ISR=100%TI=I%CI=I%TS=U)SEQ(SP=103%GCD=1%ISR=10C%TI=I%CI=I%TS=U
OS:)SEQ(SP=104%GCD=1%ISR=10E%TI=I%CI=I%TS=U)SEQ(SP=106%GCD=1%ISR=10B%TI=I%C
OS:I=I%TS=U)OPS(O1=M540NW8NNS%O2=M540NW8NNS%O3=M540NW8%O4=M540NW8NNS%O5=M54
OS:0NW8NNS%O6=M540NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)E
OS:CN(R=Y%DF=Y%T=80%W=FFFF%O=M540NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O
OS:%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=
OS:G%RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-14T00:55:41
|_  start_date: N/A

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   85.79 ms 192.168.45.1
2   85.74 ms 192.168.45.254
3   86.93 ms 192.168.251.1
4   87.02 ms 192.168.218.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 277.54 seconds
```

nxc-sweep 진행
```bash
┌──(kali㉿kali)-[~/PG/Secura/95]
└─$ nxc-sweep 192.168.218.95 -u Eric.wallows -p EricLikesRunning800                                   [*] Starting NXC sweep for 192.168.218.95 as Eric.wallows ...

[+] Port 445 open. Checking smb ...
SMB         192.168.218.95  445    SECURE           [*] Windows 10 / Server 2019 Build 19041 x64 (name:SECURE) (domain:secura.yzx) (signing:False) (SMBv1:False)
SMB         192.168.218.95  445    SECURE           [+] secura.yzx\Eric.wallows:EricLikesRunning800 (Pwn3d!)
SMB         192.168.218.95  445    SECURE           [*] Enumerated shares
SMB         192.168.218.95  445    SECURE           Share           Permissions     Remark
SMB         192.168.218.95  445    SECURE           -----           -----------     ------
SMB         192.168.218.95  445    SECURE           ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.218.95  445    SECURE           C$              READ,WRITE      Default share
SMB         192.168.218.95  445    SECURE           IPC$            READ            Remote IPC

[+] Port 5985 open. Checking winrm ...
WINRM       192.168.218.95  5985   SECURE           [*] Windows 10 / Server 2019 Build 19041 (name:SECURE) (domain:secura.yzx)
WINRM       192.168.218.95  5985   SECURE           [+] secura.yzx\Eric.wallows:EricLikesRunning800 (Pwn3d!)

[+] Port 3389 open. Checking rdp ...
RDP         192.168.218.95  3389   SECURE           [*] Windows 10 or Windows Server 2016 Build 19041 (name:SECURE) (domain:secura.yzx) (nla:True)
RDP         192.168.218.95  3389   SECURE           [+] secura.yzx\Eric.wallows:EricLikesRunning800 (Pwn3d!)

[-] Port 1433 closed/filtered. Skipping mssql

[-] Port 21 closed/filtered. Skipping ftp

[*] All active services checked.
```


44444 웹페이지 발견 후 admin/admin 으로 로그인
![[Pasted image 20260814101153.png]]





## 192.168.218.96
## 192.168.218.97