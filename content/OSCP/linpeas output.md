cat output.txt



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                             
    |---------------------------------------------------------------------------------|                             
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz         |                             
    |         Follow on Twitter         :     @hacktricks_live                        |                             
    |         Respect on HTB            :     SirBroccoli                             |                             
    |---------------------------------------------------------------------------------|                             
    |                                 Thank you!                                      |                             
    \---------------------------------------------------------------------------------/                             
          LinPEAS-ng by carlospolop                                                                                 
                                                                                                                    
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                                                  
                                                                                                                    
Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:                                                                                                            
  RED/YELLOW: 95% a PE vector
  RED: You should take a look into it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                 
                               ╚═══════════════════╝                                                                
OS: Linux version 5.15.0-52-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022
User & Groups: uid=1001(dev) gid=1001(dev) groups=1001(dev)
Hostname: oscp

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                 
[+] /usr/bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)                                                                                                      
                                                                                                                    

Caching directories DONE
                                                                                                                    
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                  
                              ╚════════════════════╝                                                                
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                   
Linux version 5.15.0-52-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                      
Sudo version 1.9.9                                                                                                  


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                              

╔══════════╣ Date & uptime
Tue Jan 13 01:48:26 AM UTC 2026                                                                                     
 01:48:26 up  2:48,  0 users,  load average: 0.09, 0.09, 0.04

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                           
/dev/disk/by-id/dm-uuid-LVM-Xh23ubh6LmUFS4am8GG0dUYUNFIp4jOmoYFuUKW9WOS0snRLs32B6qgOGMU6r1h2 / ext4 defaults 0 1    
/dev/disk/by-uuid/c64636fb-e0c8-4b66-aac4-4402ee6520a6 /boot ext4 defaults 0 1
/swap.img       none    swap    sw      0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                
sda
sda1
sda2
sda3

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                             
LESSOPEN=| /usr/bin/lesspipe %s                                                                                     
USER=dev
SHLVL=3
HOME=/home/dev
OLDPWD=/
LOGNAME=dev
_=./linpeas.sh
LANG=en_US.UTF-8
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/home/dev

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                                                                                                   
dmesg Not Found                                                                                                     
                                                                                                                    
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                  
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)                                                                

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: probable
   Tags: [ ubuntu=(22.04) ]{kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                       
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                            
═╣ PaX bins present? .............. PaX Not Found                                                                   
═╣ Execshield enabled? ............ Execshield Not Found                                                            
═╣ SELinux enabled? ............... sestatus Not Found                                                              
═╣ Seccomp enabled? ............... disabled                                                                        
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                                                    

╔══════════╣ Kernel Modules Information
══╣ Kernel modules with weak perms?                                                                                 
                                                                                                                    
══╣ Kernel modules loadable? 
Modules can be loaded                                                                                               



                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                 
                                   ╚═══════════╝                                                                    
╔══════════╣ Container related tools present (if any):
/snap/bin/lxc                                                                                                       
/usr/sbin/apparmor_parser
/usr/bin/nsenter
/usr/bin/unshare
/usr/sbin/chroot
/usr/sbin/capsh
/usr/sbin/setcap
/usr/sbin/getcap

╔══════════╣ Container details
═╣ Is this a container? ........... No                                                                              
═╣ LXC version ................ Client version: 5.0.1                                                               
Server version: unreachable
═╣ LXC info ................... lxc Not Found
═╣ Any running containers? ........ No                                                                              
                                                                                                                    


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                 
                                     ╚═══════╝                                                                      
Learn and practice cloud hacking techniques in https://training.hacktricks.xyz
                                                                                                                    
═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM or Az metadata? ............. No
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No
═╣ Azure Automation Account? ............ No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                  
                ╚════════════════════════════════════════════════╝                                                  
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected processes run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                                                                                             
root           1  0.0  0.6 102092 12940 ?        Ss   Jan12   0:03 /sbin/init                                       
root         500  0.0  1.1  80664 23932 ?        S<s  Jan12   0:00 /lib/systemd/systemd-journald
root         541  0.0  1.3 354888 27364 ?        SLsl Jan12   0:00 /sbin/multipathd -d -s
root         543  0.0  0.3  25736  6764 ?        Ss   Jan12   0:00 /lib/systemd/systemd-udevd
systemd+     724  0.0  0.3  89352  6544 ?        Ssl  Jan12   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         733  0.0  0.5  51124 11936 ?        Ss   Jan12   0:00 /usr/bin/VGAuthService
root         734  0.0  0.4 315928 10020 ?        Ssl  Jan12   0:04 /usr/bin/vmtoolsd
systemd+     820  0.0  0.3  16236  8068 ?        Ss   Jan12   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+     822  0.0  0.6  25392 12260 ?        Ss   Jan12   0:00 /lib/systemd/systemd-resolved
  └─(Caps) 0x0000000000002000=cap_net_raw
dev          841  1.3 26.0 2616748 527676 ?      Ssl  Jan12   2:11 java -jar /opt/dev/api.jar
dev         1628  0.0  0.1   7368  3416 ?        S    01:39   0:00  _ /bin/bash
dev         1630  0.0  0.1   7368  3524 ?        S    01:40   0:00      _ /bin/bash
dev         1633  0.0  0.0   5784  1056 ?        S    01:41   0:00          _ script /dev/null -c /bin/bash
dev         1634  0.0  0.2   8692  5236 pts/0    Ss   01:41   0:00              _ /bin/bash
dev        39876  0.1  0.1   4004  2948 pts/0    S+   01:48   0:00                  _ /bin/sh ./linpeas.sh
dev        43184  0.0  0.0   4004  1212 pts/0    S+   01:48   0:00                      _ /bin/sh ./linpeas.sh
dev        43188  0.0  0.1  10404  3816 pts/0    R+   01:48   0:00                      |   _ ps fauxwww
dev        43187  0.0  0.0   4004  1212 pts/0    S+   01:48   0:00                      _ /bin/sh ./linpeas.sh
root         843  0.0  0.1   6892  3048 ?        Ss   Jan12   0:00 /usr/sbin/cron -f -P
message+     845  0.0  0.2   8816  4972 ?        Ss   Jan12   0:00 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         852  0.0  0.9  32780 18936 ?        Ss   Jan12   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         853  0.0  0.3 234492  6696 ?        Ssl  Jan12   0:00 /usr/libexec/polkitd --no-debug
syslog       854  0.0  0.2 222400  5948 ?        Ssl  Jan12   0:00 /usr/sbin/rsyslogd -n -iNONE
root         856  0.0  1.4 1318624 28920 ?       Ssl  Jan12   0:00 /usr/lib/snapd/snapd
root         859  0.0  1.7 2528964 35288 ?       Ssl  Jan12   0:00 java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
root         860  0.0  0.3  15024  6240 ?        Ss   Jan12   0:00 /lib/systemd/systemd-logind
root         862  0.0  0.6 392584 12900 ?        Ssl  Jan12   0:00 /usr/libexec/udisks2/udisksd
root         870  0.0  0.0   6172  1108 tty1     Ss+  Jan12   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root         894  0.0  0.5 317008 11820 ?        Ssl  Jan12   0:00 /usr/sbin/ModemManager
root         949  0.0  1.0 109756 21416 ?        Ssl  Jan12   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
dev        20558  0.0  0.0   7368  1640 pts/0    S    01:43   0:00 bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
dev        20564  0.0  0.0   7368   248 pts/0    S    01:43   0:00  _ bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
dev        20568  0.0  0.0   7368  1932 pts/0    S    01:43   0:00  |   _ bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
dev        20575  0.0  0.0   5804  1012 pts/0    S    01:43   0:00  |       _ dd bs=9000 count=1
dev        20576  0.0  0.0   2780   940 pts/0    S    01:43   0:00  |       _ xxd
dev        20565  0.0  0.1   6608  2280 pts/0    S    01:43   0:00  _ grep accessible
dev        22445  0.0  0.0  81384   768 ?        Ss   01:43   0:00 gpg-agent --homedir /home/dev/.gnupg --use-standard-socket --daemon[0m

╔══════════╣ Processes with unusual configurations
                                                                                                                    
╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory   
gdm-password Not Found                                                                                              
gnome-keyring-daemon Not Found                                                                                      
lightdm Not Found                                                                                                   
vsftpd Not Found                                                                                                    
apache2 Not Found                                                                                                   
sshd: process found (dump creds from memory as root)                                                                
mysql Not Found
postgres Not Found                                                                                                  
redis-server Not Found                                                                                              
mongod Not Found                                                                                                    
memcached Not Found                                                                                                 
elasticsearch Not Found                                                                                             
jenkins Not Found                                                                                                   
tomcat Not Found                                                                                                    
nginx Not Found                                                                                                     
php-fpm Not Found                                                                                                   
supervisord Not Found                                                                                               
vncserver Not Found                                                                                                 
xrdp Not Found                                                                                                      
teamviewer Not Found                                                                                                
                                                                                                                    
╔══════════╣ Opened Files by processes
Process 841 (dev) - java -jar /opt/dev/api.jar                                                                      
  └─ Has open files:
    └─ /dev/urandom
    └─ pipe:[22286]
    └─ pipe:[22287]
    └─ pipe:[38127]
    └─ pipe:[38128]
    └─ pipe:[38129]
    └─ /usr/lib/jvm/java-11-openjdk-amd64/lib/modules
    └─ /usr/share/java/java-atk-wrapper.jar
    └─ /opt/dev/api.jar
    └─ /dev/random
Process 1628 (dev) - /bin/bash 
  └─ Has open files:
    └─ pipe:[38129]
Process 1630 (dev) - /bin/bash 
  └─ Has open files:
    └─ pipe:[38129]
Process 1633 (dev) - script /dev/null -c /bin/bash 
  └─ Has open files:
    └─ pipe:[38129]
    └─ /dev/ptmx
    └─ /dev/pts/0
Process 1634 (dev) - /bin/bash 
  └─ Has open files:
    └─ /dev/pts/0
Process 20558 (dev) - bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | x
  └─ Has open files:
    └─ /dev/pts/0
Process 20564 (dev) - bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | x
  └─ Has open files:
    └─ pipe:[98981]
Process 20565 (dev) - grep accessible 
  └─ Has open files:
    └─ pipe:[98981]
    └─ /dev/pts/0
Process 20568 (dev) - bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | x
  └─ Has open files:
    └─ pipe:[98981]
Process 20575 (dev) - dd bs=9000 count=1 
  └─ Has open files:
    └─ pipe:[98999]
Process 20576 (dev) - xxd 
  └─ Has open files:
    └─ pipe:[98999]
    └─ pipe:[98981]

╔══════════╣ Processes with memory-mapped credential files
                                                                                                                    
╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user                                           
                                                                                                                    
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                  
                                                                                                                    
╔══════════╣ Check for vulnerable cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                
══╣ Cron jobs list                                                                                                  
/usr/bin/crontab                                                                                                    
incrontab Not Found
-rw-r--r-- 1 root root    1136 Mar 23  2022 /etc/crontab                                                            

/etc/cron.d:
total 16
drwxr-xr-x   2 root root 4096 Nov  1  2022 .
drwxr-xr-x 106 root root 4096 Nov  7  2022 ..
-rw-r--r--   1 root root  201 Jan  8  2022 e2scrub_all
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.daily:
total 32
drwxr-xr-x   2 root root 4096 Nov  1  2022 .
drwxr-xr-x 106 root root 4096 Nov  7  2022 ..
-rwxr-xr-x   1 root root  376 Oct 26  2021 apport
-rwxr-xr-x   1 root root 1478 Apr  8  2022 apt-compat
-rwxr-xr-x   1 root root  123 Dec  5  2021 dpkg
-rwxr-xr-x   1 root root  377 Jan 24  2022 logrotate
-rwxr-xr-x   1 root root 1330 Mar 17  2022 man-db
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Apr 21  2022 .
drwxr-xr-x 106 root root 4096 Nov  7  2022 ..
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Apr 21  2022 .
drwxr-xr-x 106 root root 4096 Nov  7  2022 ..
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x   2 root root 4096 Apr 21  2022 .
drwxr-xr-x 106 root root 4096 Nov  7  2022 ..
-rwxr-xr-x   1 root root 1020 Mar 17  2022 man-db
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

SHELL=/bin/sh

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

══╣ Checking for specific cron jobs vulnerabilities
Checking cron directories...                                                                                        

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                            
══╣ Active timers:                                                                                                  
NEXT                        LEFT          LAST                        PASSED                UNIT                           ACTIVATES
Tue 2026-01-13 03:20:34 UTC 1h 31min left Mon 2022-11-07 08:07:10 UTC 3 years 2 months ago  fwupd-refresh.timer            fwupd-refresh.service
Tue 2026-01-13 04:31:09 UTC 2h 42min left Tue 2022-11-01 07:44:00 UTC 3 years 2 months ago  motd-news.timer                motd-news.service
Tue 2026-01-13 05:57:21 UTC 4h 8min left  Thu 2025-02-20 13:58:43 UTC 10 months 22 days ago ua-timer.timer                 ua-timer.service
Tue 2026-01-13 06:09:37 UTC 4h 20min left Tue 2026-01-13 00:28:41 UTC 1h 19min ago          apt-daily-upgrade.timer        apt-daily-upgrade.service
Tue 2026-01-13 07:17:32 UTC 5h 28min left Tue 2022-11-01 07:44:00 UTC 3 years 2 months ago  apt-daily.timer                apt-daily.service
Tue 2026-01-13 08:45:56 UTC 6h left       Tue 2022-11-01 07:44:00 UTC 3 years 2 months ago  update-notifier-motd.timer     update-notifier-motd.service
Tue 2026-01-13 23:05:27 UTC 21h left      Thu 2025-02-20 13:34:14 UTC 10 months 22 days ago update-notifier-download.timer update-notifier-download.service
Tue 2026-01-13 23:15:19 UTC 21h left      Thu 2025-02-20 13:44:06 UTC 10 months 22 days ago systemd-tmpfiles-clean.timer   systemd-tmpfiles-clean.service                                                                               
Wed 2026-01-14 00:00:00 UTC 22h left      Tue 2026-01-13 00:28:41 UTC 1h 19min ago          dpkg-db-backup.timer           dpkg-db-backup.service
Wed 2026-01-14 00:00:00 UTC 22h left      Tue 2026-01-13 00:28:41 UTC 1h 19min ago          logrotate.timer                logrotate.service
Wed 2026-01-14 01:48:01 UTC 23h left      Tue 2026-01-13 00:28:41 UTC 1h 19min ago          man-db.timer                   man-db.service
Sun 2026-01-18 03:10:24 UTC 5 days left   Tue 2026-01-13 00:28:41 UTC 1h 19min ago          e2scrub_all.timer              e2scrub_all.service
Mon 2026-01-19 01:23:02 UTC 5 days left   Tue 2026-01-13 00:28:41 UTC 1h 19min ago          fstrim.timer                   fstrim.service
n/a                         n/a           n/a                         n/a                   apport-autoreport.timer        apport-autoreport.service
n/a                         n/a           n/a                         n/a                   snapd.snap-repair.timer        snapd.snap-repair.service
══╣ Disabled timers:
══╣ Additional timer files:                                                                                         
                                                                                                                    
╔══════════╣ Services and Service Files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                          
                                                                                                                    
══╣ Active services:
api.service                                                                               loaded active running Api App
  Potential issue in service file: /etc/systemd/system/api.service
  └─ RELATIVE_PATH: Could be executing some relative path
apparmor.service                                                                          loaded active exited  Load AppArmor profiles
apport.service                                                                            loaded active exited  LSB: automatic crash report generation
blk-availability.service                                                                  loaded active exited  Availability of block devices
cloud-config.service                                                                      loaded active exited  Apply the settings specified in cloud-config
cloud-final.service                                                                       loaded active exited  Execute cloud user/final scripts
cloud-init-local.service                                                                  loaded active exited  Initial cloud-init job (pre-networking)
cloud-init.service                                                                        loaded active exited  Initial cloud-init job (metadata service crawler)
console-setup.service                                                                     loaded active exited  Set console font and keymap
cron.service                                                                              loaded active running Regular background program processing daemon
dbus.service                                                                              loaded active running D-Bus System Message Bus
  Potential issue in service file: /lib/systemd/system/dbus.service
  └─ RELATIVE_PATH: Could be executing some relative path
finalrd.service                                                                           loaded active exited  Create final runtime dir for shutdown pivot root
getty@tty1.service                                                                        loaded active running Getty on tty1
keyboard-setup.service                                                                    loaded active exited  Set the console keyboard layout
kmod-static-nodes.service                                                                 loaded active exited  Create List of Static Device Nodes
lvm2-monitor.service                                                                      loaded active exited  Monitoring of LVM2 mirrors, snapshots etc. using dmeventd or progress polling
lvm2-pvscan@8:3.service                                                                   loaded active exited  LVM event activation on device 8:3
ModemManager.service                                                                      loaded active running Modem Manager
  Potential issue in service: ModemManager.service
  └─ RUNS_AS_ROOT: Service runs as root
multipathd.service                                                                        loaded active running Device-Mapper Multipath Device Controller
networkd-dispatcher.service                                                               loaded active running Dispatcher daemon for systemd-networkd
open-vm-tools.service                                                                     loaded active running Service for virtual machines hosted on VMware
plymouth-quit-wait.service                                                                loaded active exited  Hold until boot process finishes up
plymouth-quit.service                                                                     loaded active exited  Terminate Plymouth Boot Screen
plymouth-read-write.service                                                               loaded active exited  Tell Plymouth To Write Out Runtime Data
polkit.service                                                                            loaded active running Authorization Manager
rsyslog.service                                                                           loaded active running System Logging Service
setvtrgb.service                                                                          loaded active exited  Set console scheme
snapd.apparmor.service                                                                    loaded active exited  Load AppArmor profiles managed internally by snapd
snapd.seeded.service                                                                      loaded active exited  Wait until snapd is fully seeded
snapd.service                                                                             loaded active running Snap Daemon
ssh.service                                                                               loaded active running OpenBSD Secure Shell server
stats.service                                                                             loaded active running Stats App
  Potential issue in service file: /etc/systemd/system/stats.service
  └─ RELATIVE_PATH: Could be executing some relative path
systemd-fsck@dev-disk-by\x2duuid-c64636fb\x2de0c8\x2d4b66\x2daac4\x2d4402ee6520a6.service loaded active exited  File System Check on /dev/disk/by-uuid/c64636fb-e0c8-4b66-aac4-4402ee6520a6
systemd-journal-flush.service                                                             loaded active exited  Flush Journal to Persistent Storage
  Potential issue in service file: /lib/systemd/system/systemd-journal-flush.service
  └─ RELATIVE_PATH: Could be executing some relative path
systemd-journald.service                                                                  loaded active running Journal Service
systemd-logind.service                                                                    loaded active running User Login Management
systemd-modules-load.service                                                              loaded active exited  Load Kernel Modules
systemd-networkd-wait-online.service                                                      loaded active exited  Wait for Network to be Configured
systemd-networkd.service                                                                  loaded active running Network Configuration
  Potential issue in service file: /lib/systemd/system/systemd-networkd.service
  └─ RELATIVE_PATH: Could be executing some relative path
systemd-random-seed.service                                                               loaded active exited  Load/Save Random Seed
systemd-remount-fs.service                                                                loaded active exited  Remount Root and Kernel File Systems
  Potential issue in service: systemd-remount-fs.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands
systemd-resolved.service                                                                  loaded active running Network Name Resolution
systemd-sysctl.service                                                                    loaded active exited  Apply Kernel Variables
systemd-sysusers.service                                                                  loaded active exited  Create System Users
  Potential issue in service file: /lib/systemd/system/systemd-sysusers.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service: systemd-sysusers.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands
systemd-timesyncd.service                                                                 loaded active running Network Time Synchronization
systemd-tmpfiles-setup-dev.service                                                        loaded active exited  Create Static Device Nodes in /dev
systemd-tmpfiles-setup.service                                                            loaded active exited  Create Volatile Files and Directories
systemd-udev-trigger.service                                                              loaded active exited  Coldplug All udev Devices
  Potential issue in service file: /lib/systemd/system/systemd-udev-trigger.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service: systemd-udev-trigger.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands
systemd-udevd.service                                                                     loaded active running Rule-based Manager for Device Events and Files
  Potential issue in service file: /lib/systemd/system/systemd-udevd.service
  └─ RELATIVE_PATH: Could be executing some relative path
systemd-update-utmp.service                                                               loaded active exited  Record System Boot/Shutdown in UTMP
systemd-user-sessions.service                                                             loaded active exited  Permit User Sessions
udisks2.service                                                                           loaded active running Disk Manager
ufw.service                                                                               loaded active exited  Uncomplicated firewall
unattended-upgrades.service                                                               loaded active running Unattended Upgrades Shutdown
vgauth.service                                                                            loaded active running Authentication service for virtual machines hosted on VMware
LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
55 loaded units listed.

══╣ Disabled services:
console-getty.service                  disabled disabled                                                            
debug-shell.service                    disabled disabled
iscsid.service                         disabled enabled
nftables.service                       disabled enabled
rsync.service                          disabled enabled
serial-getty@.service                  disabled enabled
systemd-boot-check-no-failures.service disabled disabled
systemd-network-generator.service      disabled enabled
systemd-sysext.service                 disabled enabled
  Potential issue in service file: /lib/systemd/system/systemd-sysext.service
  └─ RELATIVE_PATH: Could be executing some relative path
systemd-time-wait-sync.service         disabled disabled
upower.service                         disabled enabled
11 unit files listed.

══╣ Additional service files:
  Potential issue in service file: /etc/systemd/system/api.service                                                  
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/api.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/grub-common.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/stats.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/systemd-networkd.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service file: /etc/systemd/system/sleep.target.wants/grub-common.service
  └─ RELATIVE_PATH: Could be executing some relative path
  Potential issue in service file: /etc/systemd/system/stats.service
  └─ RELATIVE_PATH: Could be executing some relative path
You can't write on systemd PATH

╔══════════╣ Systemd Information
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths     
═╣ Systemd version and vulnerabilities? .............. 249.11                                                       
3.6
═╣ Services running as root? ..... 
═╣ Running services with dangerous capabilities? ... 
═╣ Services with writable paths? . dbus.service: Uses relative path '@dbus-daemon' (from ExecStart=@/usr/bin/dbus-daemon @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only)              
networkd-dispatcher.service: Uses relative path '$networkd_dispatcher_args' (from ExecStart=/usr/bin/networkd-dispatcher $networkd_dispatcher_args)                                                                                     
rsyslog.service: Uses relative path '-n' (from ExecStart=/usr/sbin/rsyslogd -n -iNONE)

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths     
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                         

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                           
                                                                                                                    
╔══════════╣ Unix Sockets Analysis
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                           
/home/dev/.gnupg/S.gpg-agent                                                                                        
  └─(Read Write Execute )
/home/dev/.gnupg/S.gpg-agent.browser
  └─(Read Write Execute )
/home/dev/.gnupg/S.gpg-agent.extra
  └─(Read Write Execute )
/home/dev/.gnupg/S.gpg-agent.ssh
  └─(Read Write Execute )
/run/dbus/system_bus_socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/snapd-snap.socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/snapd.socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/fsck.progress
/run/systemd/inaccessible/sock
/run/systemd/io.system.ManagedOOM
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/dev-log
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/stdout
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/syslog
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/notify
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/run/systemd/private
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/run/systemd/resolve/io.systemd.Resolve
  └─(Read Write (Weak Permissions: 666) )
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/udev/control
/run/uuidd/request
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/vmware/guestServicePipe
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/var/run/vmware/guestServicePipe
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/var/snap/lxd/common/lxd/unix.socket
/var/snap/lxd/common/lxd-user/unix.socket

╔══════════╣ D-Bus Analysis
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                             
NAME                            PID PROCESS         USER             CONNECTION    UNIT                        SESSION DESCRIPTION
:1.0                            724 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service   -       -
:1.1                            822 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service    -       -
:1.10                           856 snapd           root             :1.10         snapd.service               -       -
:1.1009                       59827 busctl          dev              :1.1009       api.service                 -       -
:1.11                           949 unattended-upgr root             :1.11         unattended-upgrades.service -       -
:1.2                            820 systemd-network systemd-network  :1.2          systemd-networkd.service    -       -
:1.3                              1 systemd         root             :1.3          init.scope                  -       -
:1.4                            853 polkitd         root             :1.4          polkit.service              -       -
:1.5                            862 udisksd         root             :1.5          udisks2.service             -       -
:1.6                            894 ModemManager    root             :1.6          ModemManager.service        -       -
:1.7                            860 systemd-logind  root             :1.7          systemd-logind.service      -       -
:1.9                            852 networkd-dispat root             :1.9          networkd-dispatcher.service -       -
com.ubuntu.SoftwareProperties     - -               -                (activatable) -                           -       -
io.netplan.Netplan                - -               -                (activatable) -                           -       -
org.freedesktop.DBus              1 systemd         root             -             init.scope                  -       -
org.freedesktop.ModemManager1   894 ModemManager    root             :1.6          ModemManager.service        -       -
org.freedesktop.PackageKit        - -               -                (activatable) -                           -       -
org.freedesktop.PolicyKit1      853 polkitd         root             :1.4          polkit.service              -       -
org.freedesktop.UDisks2         862 udisksd         root             :1.5          udisks2.service             -       -
org.freedesktop.UPower            - -               -                (activatable) -                           -       -
org.freedesktop.bolt              - -               -                (activatable) -                           -       -
org.freedesktop.fwupd             - -               -                (activatable) -                           -       -
org.freedesktop.hostname1         - -               -                (activatable) -                           -       -
org.freedesktop.locale1           - -               -                (activatable) -                           -       -
org.freedesktop.login1          860 systemd-logind  root             :1.7          systemd-logind.service      -       -
org.freedesktop.network1        820 systemd-network systemd-network  :1.2          systemd-networkd.service    -       -
org.freedesktop.resolve1        822 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service    -       -
org.freedesktop.systemd1          1 systemd         root             :1.3          init.scope                  -       -
org.freedesktop.thermald          - -               -                (activatable) -                           -       -
org.freedesktop.timedate1         - -               -                (activatable) -                           -       -
org.freedesktop.timesync1       724 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service   -       -

╔══════════╣ D-Bus Configuration Files
Analyzing /etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf:                                                  
  └─(Allow rules in default context)
             └─     <allow send_destination="com.ubuntu.SoftwareProperties"
            <allow send_destination="com.ubuntu.SoftwareProperties"
            <allow send_destination="com.ubuntu.DeviceDriver"
Analyzing /etc/dbus-1/system.d/org.freedesktop.ModemManager1.conf:
  └─(Allow rules in default context)
             └─     <!-- Methods listed here are explicitly allowed or PolicyKit protected.
Analyzing /etc/dbus-1/system.d/org.freedesktop.PackageKit.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.PackageKit"
            <allow send_destination="org.freedesktop.PackageKit"
            <allow send_destination="org.freedesktop.PackageKit"
Analyzing /etc/dbus-1/system.d/org.freedesktop.thermald.conf:
  └─(Weak group policy found)
     └─         <policy group="power">
  └─(Allow rules in default context)
             └─                 <allow receive_sender="org.freedesktop.thermald"/>
                        <allow send_destination="org.freedesktop.thermald"/>

══╣ D-Bus Session Bus Analysis
(Access to session bus available)                                                                                   


╔══════════╣ Legacy r-commands (rsh/rlogin/rexec) and host-based trust
                                                                                                                    
══╣ Listening r-services (TCP 512-514)
                                                                                                                    
══╣ systemd units exposing r-services
rlogin|rsh|rexec units Not Found                                                                                    
                                                                                                                    
══╣ inetd/xinetd configuration for r-services
/etc/inetd.conf Not Found                                                                                           
/etc/xinetd.d Not Found                                                                                             
                                                                                                                    
══╣ Installed r-service server packages
  No related packages found via dpkg                                                                                

══╣ /etc/hosts.equiv and /etc/shosts.equiv
                                                                                                                    
══╣ Per-user .rhosts files
.rhosts Not Found                                                                                                   
                                                                                                                    
══╣ PAM rhosts authentication
/etc/pam.d/rlogin|rsh Not Found                                                                                     
                                                                                                                    
══╣ SSH HostbasedAuthentication
  HostbasedAuthentication no or not set                                                                             

══╣ Potential DNS control indicators (local)
  Not detected                                                                                                      

╔══════════╣ Crontab UI (root) misconfiguration checks
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                
crontab-ui Not Found                                                                                                
                                                                                                                    

                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                 
                              ╚═════════════════════╝                                                               
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                 
link-local 169.254.0.0
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.162.150  netmask 255.255.255.0  broadcast 192.168.162.255
        ether 00:50:56:ab:67:44  txqueuelen 1000  (Ethernet)
        RX packets 1972107  bytes 160970005 (160.9 MB)
        RX errors 0  dropped 274  overruns 0  frame 0
        TX packets 522395  bytes 93105733 (93.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8749  bytes 711992 (711.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8749  bytes 711992 (711.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Hostname, hosts and DNS
══╣ Hostname Information                                                                                            
System hostname: oscp                                                                                               
FQDN: oscp

══╣ Hosts File Information
Contents of /etc/hosts:                                                                                             
  127.0.0.1 localhost
  127.0.1.1 berlin
  ::1     ip6-localhost ip6-loopback
  fe00::0 ip6-localnet
  ff00::0 ip6-mcastprefix
  ff02::1 ip6-allnodes
  ff02::2 ip6-allrouters

══╣ DNS Configuration
DNS Servers (resolv.conf):                                                                                          
  127.0.0.53
  search .
-e 
Systemd-resolved configuration:
  [Resolve]
-e 
NetworkManager DNS settings:
-e 
DNS Domain Information:
(none)

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                        
══╣ Active Ports (netstat)                                                                                          
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      841/java            

╔══════════╣ Network Traffic Analysis Capabilities
                                                                                                                    
══╣ Available Sniffing Tools
tcpdump is available                                                                                                
tcpdump version 4.99.1

══╣ Network Interfaces Sniffing Capabilities
Interface ens160: Not sniffable                                                                                     
No sniffable interfaces found

╔══════════╣ Firewall Rules Analysis
                                                                                                                    
══╣ Iptables Rules
No permission to list iptables rules                                                                                

══╣ Nftables Rules
No permission to list nftables rules                                                                                

══╣ Firewalld Rules
firewalld Not Found                                                                                                 
                                                                                                                    
══╣ UFW Rules
UFW is not running                                                                                                  

╔══════════╣ Inetd/Xinetd Services Analysis
                                                                                                                    
══╣ Inetd Services
inetd Not Found                                                                                                     
                                                                                                                    
══╣ Xinetd Services
xinetd Not Found                                                                                                    
                                                                                                                    
══╣ Running Inetd/Xinetd Services
Active Services (from netstat):                                                                                     
-e 
Active Services (from ss):
-e 
Running Service Processes:

╔══════════╣ Internet Access?
Port 443 is accessible with curl                                                                                    
DNS is not accessible
Port 443 is not accessible
ICMP is not accessible
Port 80 is not accessible

╔══════════╣ Is hostname malicious or leaked?
╚ This will check the public IP and hostname in known malicious lists and leaks to find any relevant information about the host.                                                                                                        
ICMP is not accessible                                                                                              
{
    "hostname": "oscp",
    "source_ip": "139.99.71.1",
    "checks": {
        "IP in VirusTotal": {
            "malicious": false,
            "reason": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 93,
                "harmless": 0,
                "timeout": 0
            },
            "reputation": 0
        },
        "IP in AbuseIPDB": {
            "malicious": false,
            "abuseConfidenceScore": 0,
            "countryCode": "SG",
            "totalReports": 0,
            "lastReportedAt": null
        },
        "Hostname in Pastes": {
            "error": "HTTP Error 400: Bad Request"
        },
        "IP in MalwareWorld": {
            "found": false,
            "malicious": false
        },
        "Hostname in MalwareWorld": {
            "found": false,
            "malicious": false
        }
    }
}


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                 
                               ╚═══════════════════╝                                                                
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                             
uid=1001(dev) gid=1001(dev) groups=1001(dev)                                                                        

╔══════════╣ PGP Keys and Related Files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#pgp-keys                          
GPG:                                                                                                                
GPG is installed, listing keys:
-e 
NetPGP:
netpgpkeys Not Found
-e                                                                                                                  
PGP Related Files:
Found: /home/dev/.gnupg
total 20
drwx------ 3 dev dev 4096 Jan 13 01:48 .
drwxr-x--- 4 dev dev 4096 Jan 13 01:46 ..
drwx------ 2 dev dev 4096 Jan 13 01:43 private-keys-v1.d
-rw------- 1 dev dev   32 Jan 13 01:43 pubring.kbx
srwx------ 1 dev dev    0 Jan 13 01:43 S.gpg-agent
srwx------ 1 dev dev    0 Jan 13 01:43 S.gpg-agent.browser
srwx------ 1 dev dev    0 Jan 13 01:43 S.gpg-agent.extra
srwx------ 1 dev dev    0 Jan 13 01:43 S.gpg-agent.ssh
-rw------- 1 dev dev 1200 Jan 13 01:43 trustdb.gpg

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                     
                                                                                                                    

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens               
ptrace protection is enabled (1)                                                                                    

doas.conf Not Found
                                                                                                                    
╔══════════╣ Checking Pkexec and Polkit
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2                                                                                                             
                                                                                                                    
══╣ Polkit Binary
Pkexec binary found at: /usr/bin/pkexec                                                                             
Pkexec binary has SUID bit set!
-rwsr-xr-x 1 root root 30872 Feb 26  2022 /usr/bin/pkexec
pkexec version 0.105

══╣ Polkit Policies
Checking /etc/polkit-1/localauthority.conf.d/:                                                                      

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin
Checking /usr/share/polkit-1/rules.d/:
// -*- mode: js2 -*-
polkit.addRule(function(action, subject) {
    if ((action.id === "org.freedesktop.bolt.enroll" ||
         action.id === "org.freedesktop.bolt.authorize" ||
         action.id === "org.freedesktop.bolt.manage") &&
        subject.active === true && subject.local === true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.fwupd.update-internal" &&
        subject.active == true && subject.local == true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.packagekit.upgrade-system" ||
         action.id == "org.freedesktop.packagekit.trigger-offline-update") &&
        subject.active == true && subject.local == true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});
// This file is part of systemd.
// See systemd-networkd.service(8) and polkit(8) for more information.

// Allow systemd-networkd to set timezone, get product UUID,
// and transient hostname
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.hostname1.set-hostname" ||
         action.id == "org.freedesktop.hostname1.get-product-uuid" ||
         action.id == "org.freedesktop.timedate1.set-timezone") &&
        subject.user == "systemd-network") {
        return polkit.Result.YES;
    }
});

══╣ Polkit Authentication Agent
root         853  0.0  0.3 234492  6696 ?        Ssl  Jan12   0:00 /usr/libexec/polkitd --no-debug                  

╔══════════╣ Superusers and UID 0 Users
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html       
                                                                                                                    
══╣ Users with UID 0 in /etc/passwd
root:x:0:0:root:/root:/bin/bash                                                                                     

══╣ Users with sudo privileges in sudoers
                                                                                                                    
╔══════════╣ Users with console
dev:x:1001:1001:,,,:/home/dev:/bin/bash                                                                             
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:user:/home/user:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                              
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
uid=1001(dev) gid=1001(dev) groups=1001(dev)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=101(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=102(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=103(messagebus) gid=104(messagebus) groups=104(messagebus)
uid=104(systemd-timesync) gid=105(systemd-timesync) groups=105(systemd-timesync)
uid=105(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=106(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(syslog) gid=113(syslog) groups=113(syslog),4(adm)
uid=108(uuidd) gid=114(uuidd) groups=114(uuidd)
uid=109(tcpdump) gid=115(tcpdump) groups=115(tcpdump)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(tss) gid=116(tss) groups=116(tss)
uid=111(landscape) gid=117(landscape) groups=117(landscape)
uid=112(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=113(fwupd-refresh) gid=118(fwupd-refresh) groups=118(fwupd-refresh)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=999(lxd) gid=100(users) groups=100(users)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Currently Logged in Users
                                                                                                                    
══╣ Basic user information
 01:49:00 up  2:48,  0 users,  load average: 0.22, 0.12, 0.06                                                       
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

══╣ Active sessions
 01:49:00 up  2:48,  0 users,  load average: 0.22, 0.12, 0.06                                                       
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

══╣ Logged in users (utmp)
           system boot  2025-02-20 13:29                                                                            
           run-level 5  2025-02-20 13:29
LOGIN      tty1         2025-02-20 13:29               870 id=tty1

══╣ SSH sessions
                                                                                                                    
══╣ Screen sessions
No Sockets found in /run/screen/S-dev.                                                                              


══╣ Tmux sessions
                                                                                                                    
╔══════════╣ Last Logons and Login History
                                                                                                                    
══╣ Last logins
reboot   system boot  5.15.0-52-generi Thu Feb 20 13:29   still running                                             
reboot   system boot  5.15.0-52-generi Wed Feb 12 22:04   still running
user     tty1                          Mon Nov  7 12:14 - 12:15  (00:00)
reboot   system boot  5.15.0-52-generi Mon Nov  7 12:14 - 12:15  (00:01)
root     pts/0        192.168.118.4    Mon Nov  7 11:07 - down   (00:00)
root     pts/0        192.168.118.4    Mon Nov  7 11:07 - 11:07  (00:00)
reboot   system boot  5.15.0-52-generi Mon Nov  7 11:05 - 11:08  (00:02)
root     pts/0        192.168.118.4    Mon Nov  7 11:01 - down   (00:03)
reboot   system boot  5.15.0-52-generi Mon Nov  7 11:00 - 11:05  (00:05)
root     pts/2        192.168.118.4    Mon Nov  7 08:32 - 08:32  (00:00)
root     pts/1        192.168.118.4    Mon Nov  7 08:09 - down   (00:52)
user     tty1                          Mon Nov  7 08:04 - down   (00:57)
reboot   system boot  5.15.0-52-generi Mon Nov  7 08:01 - 09:01  (01:00)
user     tty1                          Tue Nov  1 07:52 - down   (01:06)
reboot   system boot  5.15.0-25-generi Tue Nov  1 07:41 - 08:58  (01:16)

wtmp begins Tue Nov  1 07:41:53 2022

══╣ Failed login attempts
                                                                                                                    
══╣ Recent logins from auth.log (limit 20)
                                                                                                                    
══╣ Last time logon each user
Username         Port     From             Latest                                                                   
root             pts/0    192.168.118.4    Mon Nov  7 11:07:46 +0000 2022
user             tty1                      Mon Nov  7 12:14:59 +0000 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)                                                                                 
                                                                                                                    
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                    


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                  
                             ╚══════════════════════╝                                                               
╔══════════╣ Useful software
/usr/bin/base64                                                                                                     
/usr/bin/curl
/snap/bin/lxc
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
                                                                                                                    
╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Nov  1  2021 /usr/share/doc/rsync/examples/rsyncd.conf                                  
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov  1  2022 /etc/pam.d                                                                 
-rw-r--r-- 1 root root 2133 Feb 25  2022 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                
drwxr-xr-x 2 root root 4096 Nov  1  2022 /etc/ldap


╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3787 Oct  3  2022 /etc/cloud/cloud.cfg                                                       
     lock_passwd: True
-rw-r--r-- 1 root root 3807 Nov  3  2021 /snap/core20/1405/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3674 Jun 15  2022 /snap/core20/1634/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr  8  2022 /etc/apt/keyrings                                                          
drwxr-xr-x 2 root root 200 Mar 18  2022 /snap/core20/1405/usr/share/keyrings
drwxr-xr-x 2 root root 200 Sep 19  2022 /snap/core20/1634/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Nov  1  2022 /usr/share/keyrings




╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 826 Nov 15  2021 /usr/share/bash-completion/completions/bind                                 
-rw-r--r-- 1 root root 826 Nov 15  2021 /usr/share/bash-completion/completions/bind




╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Jan  6  2022 /etc/skel/.bashrc                                                          
-rw-r--r-- 1 dev dev 3771 Nov  7  2022 /home/dev/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1405/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1634/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Jan  6  2022 /etc/skel/.profile
-rw-r--r-- 1 dev dev 807 Nov  7  2022 /home/dev/.profile
-rw-r--r-- 1 root root 807 Feb 25  2020 /snap/core20/1405/etc/skel/.profile
-rw-r--r-- 1 root root 807 Feb 25  2020 /snap/core20/1634/etc/skel/.profile




╔══════════╣ Analyzing FreeIPA Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov  1  2022 /usr/src/linux-headers-5.15.0-25/drivers/net/ipa                           

drwxr-xr-x 2 root root 4096 Nov  1  2022 /usr/src/linux-headers-5.15.0-52/drivers/net/ipa




╔══════════╣ Searching mysql credentials and exec
                                                                                                                    
MySQL process not found.
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                        
netpgpkeys Not Found
netpgp Not Found                                                                                                    
                                                                                                                    
-rw-r--r-- 1 root root 2794 Mar 26  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 26  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw------- 1 dev dev 1200 Jan 13 01:43 /home/dev/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /snap/core20/1405/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /snap/core20/1405/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /snap/core20/1405/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /snap/core20/1405/usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /snap/core20/1405/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /snap/core20/1634/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /snap/core20/1634/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /snap/core20/1634/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /snap/core20/1634/usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /snap/core20/1634/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2899 Jul  4  2022 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 2247 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-cc-eal.gpg
-rw-r--r-- 1 root root 2274 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-cis.gpg
-rw-r--r-- 1 root root 2236 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-esm-infra-trusty.gpg
-rw-r--r-- 1 root root 2275 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-fips.gpg
-rw-r--r-- 1 root root 2250 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-realtime-kernel.gpg
-rw-r--r-- 1 root root 2235 Sep 27  2022 /usr/share/keyrings/ubuntu-advantage-ros.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 3023 Mar 26  2021 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg


drwx------ 3 dev dev 4096 Jan 13 01:49 /home/dev/.gnupg


╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                      
passwd file: /etc/passwd
passwd file: /snap/core20/1405/etc/pam.d/passwd
passwd file: /snap/core20/1405/etc/passwd
passwd file: /snap/core20/1405/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1405/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1405/var/lib/extrausers/passwd
passwd file: /snap/core20/1634/etc/pam.d/passwd
passwd file: /snap/core20/1634/etc/passwd
passwd file: /snap/core20/1634/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1634/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1634/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                         
                                                                                                                    




-rw-r--r-- 1 root root 601 Nov  1  2022 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 173 Nov  1  2022 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 93 Nov  1  2022 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 565 Nov  1  2022 /etc/ssh/ssh_host_rsa_key.pub

PermitRootLogin yes
UsePAM yes
PasswordAuthentication yes
══╣ Some certificates were found (out limited):
/etc/pki/fwupd/LVFS-CA.pem                                                                                          
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
39876PSTORAGE_CERTSBIN

══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent.socket                                                             
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/home/dev/.gnupg/S.gpg-agent.browser
/home/dev/.gnupg/S.gpg-agent.extra
/home/dev/.gnupg/S.gpg-agent.ssh
/home/dev/.gnupg/S.gpg-agent
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                                                                      
Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                    


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions               
tmux 3.2a                                                                                                           


/tmp/tmux-1001



                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                  
                      ╚════════════════════════════════════╝                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                     
-rwsr-xr-x 1 root root 121K Sep 29  2022 /snap/snapd/17336/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)                                                                     
-rwsr-xr-x 1 root root 121K Apr  8  2022 /snap/snapd/15534/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)                                                                     
-rwsr-xr-x 1 root root 84K Jul 14  2021 /snap/core20/1405/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Jul 14  2021 /snap/core20/1405/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Jul 14  2021 /snap/core20/1405/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Feb  7  2022 /snap/core20/1405/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                            
-rwsr-xr-x 1 root root 44K Jul 14  2021 /snap/core20/1405/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Jul 14  2021 /snap/core20/1405/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                 
-rwsr-xr-x 1 root root 67K Feb  7  2022 /snap/core20/1405/usr/bin/su
-rwsr-xr-x 1 root root 163K Jan 19  2021 /snap/core20/1405/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                                                                                  
-rwsr-xr-x 1 root root 39K Feb  7  2022 /snap/core20/1405/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Jun 11  2020 /snap/core20/1405/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Dec  2  2021 /snap/core20/1405/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 84K Mar 14  2022 /snap/core20/1634/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Mar 14  2022 /snap/core20/1634/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Mar 14  2022 /snap/core20/1634/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Feb  7  2022 /snap/core20/1634/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                            
-rwsr-xr-x 1 root root 44K Mar 14  2022 /snap/core20/1634/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Mar 14  2022 /snap/core20/1634/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                 
-rwsr-xr-x 1 root root 67K Feb  7  2022 /snap/core20/1634/usr/bin/su
-rwsr-xr-x 1 root root 163K Jan 19  2021 /snap/core20/1634/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                                                                                  
-rwsr-xr-x 1 root root 39K Feb  7  2022 /snap/core20/1634/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Apr 29  2022 /snap/core20/1634/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Mar 30  2022 /snap/core20/1634/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 19K Feb 26  2022 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-x 1 root root 136K Oct 17  2022 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)                                                                                      
-rwsr-xr-- 1 root messagebus 35K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 331K Feb 25  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 59K Mar 14  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                  
-rwsr-xr-x 1 root root 35K Feb 21  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 35K Mar 23  2022 /usr/bin/fusermount3
-rwsr-xr-x 1 root root 55K Feb 21  2022 /usr/bin/su
-rwsr-xr-x 1 root root 31K Feb 26  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034                                                                                          
-rwsr-xr-x 1 root root 47K Feb 21  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                             
-rwsr-xr-x 1 root root 40K Mar 14  2022 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 227K Aug  4  2022 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 72K Mar 14  2022 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 71K Mar 14  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44K Mar 14  2022 /usr/bin/chsh

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                     
-rwxr-sr-x 1 root shadow 83K Jul 14  2021 /snap/core20/1405/usr/bin/chage                                           
-rwxr-sr-x 1 root shadow 31K Jul 14  2021 /snap/core20/1405/usr/bin/expiry
-rwxr-sr-x 1 root systemd-timesync 343K Dec  2  2021 /snap/core20/1405/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /snap/core20/1405/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1405/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1405/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 83K Mar 14  2022 /snap/core20/1634/usr/bin/chage
-rwxr-sr-x 1 root shadow 31K Mar 14  2022 /snap/core20/1634/usr/bin/expiry
-rwxr-sr-x 1 root systemd-timesync 343K Mar 30  2022 /snap/core20/1634/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /snap/core20/1634/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1634/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1634/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 15K Mar 24  2022 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 23K Mar 24  2022 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 27K Mar 24  2022 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root tty 23K Feb 21  2022 /usr/bin/wall
-rwxr-sr-x 1 root crontab 39K Mar 23  2022 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 23K Mar 14  2022 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 71K Mar 14  2022 /usr/bin/chage
-rwxr-sr-x 1 root _ssh 287K Feb 25  2022 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 23K Feb 21  2022 /usr/bin/write.ul (Unknown SGID binary)

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                              
files with acls in searched folders Not Found                                                                       
                                                                                                                    
╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                      
══╣ Current shell capabilities                                                                                      
CapInh:  [Invalid capability format]                                                                                
CapPrm:  [Invalid capability format]
CapEff:  [Invalid capability format]
CapBnd:  [Invalid capability format]
CapAmb:  [Invalid capability format]

╚ Parent process capabilities
CapInh:  [Invalid capability format]                                                                                
CapPrm:  [Invalid capability format]
CapEff:  [Invalid capability format]
CapBnd:  [Invalid capability format]
CapAmb:  [Invalid capability format]


Files with capabilities (limited to 50):
/snap/core20/1405/usr/bin/ping cap_net_raw=ep
/snap/core20/1634/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                      
                                                                                                                    
╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                              
/etc/ld.so.conf                                                                                                     
Content of /etc/ld.so.conf:                                                                                         
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                                                       
  - /usr/local/lib                                                                                                  
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu                                                                                 
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                                                                     
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                    
total 40                                                                                                            
drwxr-xr-x   2 root root 4096 Nov  1  2022 .
drwxr-xr-x 106 root root 4096 Nov  7  2022 ..
-rw-r--r--   1 root root   96 Oct 15  2021 01-locale-fix.sh
-rw-r--r--   1 root root  835 Apr  8  2022 apps-bin-path.sh
-rw-r--r--   1 root root  726 Nov 15  2021 bash_completion.sh
-rw-r--r--   1 root root 1107 Mar 23  2022 gawk.csh
-rw-r--r--   1 root root  757 Mar 23  2022 gawk.sh
-rw-r--r--   1 root root 1557 Feb 17  2020 Z97-byobu.sh
-rwxr-xr-x   1 root root  873 Apr  6  2022 Z99-cloudinit-warnings.sh
-rwxr-xr-x   1 root root 3417 Apr  6  2022 Z99-cloud-locale-test.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd        
                                                                                                                    
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3461 Jul 19  2022 sbin.dhclient                                                             
-rw-r--r-- 1 root root  3448 Mar 17  2022 usr.bin.man
-rw-r--r-- 1 root root  1421 Jun 20  2021 usr.bin.tcpdump
-rw-r--r-- 1 root root 28376 Apr  8  2022 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1592 Nov 16  2021 usr.sbin.rsyslogd

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                        
═╣ Credentials in fstab/mtab? ........... No                                                                        
═╣ Can I read shadow files? ............. No                                                                        
═╣ Can I read shadow plists? ............ No                                                                        
═╣ Can I write shadow plists? ........... No                                                                        
═╣ Can I read opasswd file? ............. No                                                                        
═╣ Can I write in network-scripts? ...... No                                                                        
═╣ Can I read root folder? .............. No                                                                        
                                                                                                                    
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                              
/home/dev/.bash_history
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
                                                                                                                    
╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                    
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                    
/dev/mqueue                                                                                                         
/dev/shm
/home/dev
/run/lock
/run/screen
/run/screen/S-dev
/snap/core20/1405/run/lock
/snap/core20/1405/tmp
/snap/core20/1405/var/tmp
/snap/core20/1634/run/lock
/snap/core20/1634/tmp
/snap/core20/1634/var/tmp
/tmp
/tmp/.font-unix
/tmp/hsperfdata_dev
/tmp/hsperfdata_dev/841
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/tmux-1001
/tmp/tomcat.5768249241265866641.8080
/tmp/tomcat.5768249241265866641.8080/work
/tmp/tomcat.5768249241265866641.8080/work/Tomcat
/tmp/tomcat.5768249241265866641.8080/work/Tomcat/localhost
/tmp/tomcat.5768249241265866641.8080/work/Tomcat/localhost/ROOT
/tmp/tomcat-docbase.1112367279014276408.8080
/tmp/.X11-unix
/tmp/.XIM-unix
/var/crash
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                    
                                                                                                                    


                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                 
                            ╚═════════════════════════╝                                                             
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path            
/usr/bin/rescan-scsi-bus.sh                                                                                         
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2026-01-13+01:46:18.3717833250 /home/dev/compile.sh                                                                 
2026-01-13+01:25:34.8918412130 /home/dev/linpeas.sh
2022-11-01+07:41:57.4799997570 /etc/console-setup/cached_setup_terminal.sh
2022-11-01+07:41:57.4799997570 /etc/console-setup/cached_setup_keyboard.sh
2022-11-01+07:41:57.4799997570 /etc/console-setup/cached_setup_font.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 16                                                                                                            
drwxr-xr-x  4 root root 4096 Nov  7  2022 .
drwxr-xr-x 19 root root 4096 Nov  1  2022 ..
drwxr-xr-x  2 root root 4096 Nov  7  2022 dev
drwxr-xr-x  2 root root 4096 Nov  7  2022 stats

╔══════════╣ Unexpected in root
/swap.img                                                                                                           

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/home/dev/output.txt                                                                                                
/home/dev/compile.sh
/home/dev/exploit-1.c
/home/dev/exploit-2.c
/var/log/auth.log
/var/log/syslog
/var/log/journal/8267895545834a90b9ac66256fe0e18d/user-1001.journal
/var/log/journal/8267895545834a90b9ac66256fe0e18d/system.journal
/tmp/hsperfdata_dev/841

╔══════════╣ Syslog configuration (limit 50)
                                                                                                                    


module(load="imuxsock") # provides support for local system logging



module(load="imklog" permitnonkernelfacility="on")


$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

$RepeatedMsgReduction on

$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

$WorkDirectory /var/spool/rsyslog

$IncludeConfig /etc/rsyslog.d/*.conf
╔══════════╣ Auditd configuration (limit 50)
auditd configuration Not Found                                                                                      
╔══════════╣ Log files with potentially weak perms (limit 50)                                                       
     1644      4 -rw-r-----   1 syslog   adm           234 Feb 20  2025 /var/log/auth.log.2.gz                      
      379    104 -rw-r-----   1 root     adm        106253 Feb 12  2025 /var/log/dmesg.0
     1671      4 -rw-r-----   1 syslog   adm           828 Feb 12  2025 /var/log/auth.log.3.gz
       84     24 -rw-r-----   1 root     adm         21993 Nov  7  2022 /var/log/dmesg.2.gz
     1716      4 -rw-r-----   1 syslog   adm           432 Jan 13 01:43 /var/log/kern.log
      341    100 -rw-r-----   1 syslog   adm         94387 Jan 13 00:28 /var/log/syslog.1
     1717      4 -rw-r-----   1 syslog   adm          1836 Jan 13 01:49 /var/log/auth.log
      494     24 -rw-r-----   1 root     adm         22143 Nov  7  2022 /var/log/dmesg.3.gz
      106    304 -rw-r--r--   1 syslog   adm        304209 Feb 20  2025 /var/log/cloud-init.log
     1647     12 -rw-r-----   1 syslog   adm         10242 Jan 13 01:48 /var/log/syslog
     1640     24 -rw-r-----   1 syslog   adm         21137 Feb 20  2025 /var/log/kern.log.2.gz
      406     32 -rw-r-----   1 syslog   adm         30792 Feb 20  2025 /var/log/syslog.2.gz
      353    104 -rw-r-----   1 root     adm        105853 Feb 20  2025 /var/log/dmesg
     1564      0 -rw-r-----   1 root     adm             0 Feb 12  2025 /var/log/apt/term.log
     1633      4 -rw-r-----   1 root     adm           614 Nov  7  2022 /var/log/apt/term.log.1.gz
      346     24 -rw-r-----   1 root     adm         22174 Nov  7  2022 /var/log/dmesg.1.gz
     1673    120 -rw-r-----   1 syslog   adm        122460 Feb 12  2025 /var/log/syslog.3.gz
     1682      4 -rw-r-----   1 syslog   adm           623 Feb 20  2025 /var/log/auth.log.1
     1676      4 -rw-r-----   1 syslog   adm           768 Jan 13 00:28 /var/log/kern.log.1
      127     16 -rw-r-----   1 root     adm                14274 Feb 20  2025 /var/log/cloud-init-output.log
      337    128 -rw-r-----   1 syslog   adm               128131 Feb 12  2025 /var/log/kern.log.3.gz

╔══════════╣ Files inside /home/dev (limit 20)
total 1148                                                                                                          
drwxr-x--- 4 dev  dev    4096 Jan 13 01:46 .
drwxr-xr-x 4 root root   4096 Nov  7  2022 ..
lrwxrwxrwx 1 root root      9 Nov  7  2022 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev     220 Nov  7  2022 .bash_logout
-rw-r--r-- 1 dev  dev    3771 Nov  7  2022 .bashrc
-rwxrwxrwx 1 dev  dev      71 Jan 13 01:46 compile.sh
-rw-r--r-- 1 dev  dev    5364 Jan 13 01:46 exploit-1.c
-rw-r--r-- 1 dev  dev    7752 Jan 13 01:46 exploit-2.c
drwx------ 3 dev  dev    4096 Jan 13 01:49 .gnupg
-rwxr--r-- 1 dev  dev  975444 Jan 13 01:25 linpeas.sh
-rw-r----- 1 dev  dev      33 Jan 13 00:29 local.txt
-rw-r--r-- 1 dev  dev  143260 Jan 13 01:49 output.txt
-rw-r--r-- 1 dev  dev     807 Nov  7  2022 .profile
drwx------ 3 dev  dev    4096 Jan 13 01:43 snap

╔══════════╣ Files inside others home (limit 20)
                                                                                                                    
╔══════════╣ Searching installed mail applications
                                                                                                                    
╔══════════╣ Mails (limit 50)
                                                                                                                    
╔══════════╣ Backup folders
drwxr-xr-x 2 root root 3 Apr 15  2020 /snap/core20/1405/var/backups                                                 
total 0

drwxr-xr-x 2 root root 3 Apr 15  2020 /snap/core20/1634/var/backups
total 0

drwxr-xr-x 2 root root 4096 Jan 13 00:28 /var/backups
total 860
-rw-r--r-- 1 root root  81920 Jan 13 00:28 alternatives.tar.0
-rw-r--r-- 1 root root  44285 Nov  7  2022 apt.extended_states.0
-rw-r--r-- 1 root root   3966 Nov  1  2022 apt.extended_states.1.gz
-rw-r--r-- 1 root root      0 Jan 13 00:28 dpkg.arch.0
-rw-r--r-- 1 root root    268 Nov  1  2022 dpkg.diversions.0
-rw-r--r-- 1 root root    100 Apr 21  2022 dpkg.statoverride.0
-rw-r--r-- 1 root root 740381 Nov  7  2022 dpkg.status.0


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 61 Nov  1  2022 /var/lib/systemd/deb-systemd-helper-enabled/dpkg-db-backup.timer.dsh-also    
-rw-r--r-- 1 root root 0 Apr 21  2022 /var/lib/systemd/deb-systemd-helper-enabled/timers.target.wants/dpkg-db-backup.timer
-rw-r--r-- 1 root root 2403 Apr 21  2022 /etc/apt/sources.list.curtin.old
-rwxr-xr-x 1 root root 2196 May 25  2022 /usr/libexec/dpkg/dpkg-db-backup
-rw-r--r-- 1 root root 44008 Aug 16  2022 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 13049 Oct 13  2022 /usr/lib/modules/5.15.0-52-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 10833 Oct 13  2022 /usr/lib/modules/5.15.0-52-generic/kernel/drivers/power/supply/wm831x_backup.ko                                                                                                               
-rw-r--r-- 1 root root 11977 Mar 30  2022 /usr/lib/modules/5.15.0-25-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 10105 Mar 30  2022 /usr/lib/modules/5.15.0-25-generic/kernel/drivers/power/supply/wm831x_backup.ko                                                                                                               
-rw-r--r-- 1 root root 1802 Aug 15  2022 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 1423 Nov  1  2022 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-310.pyc                                                                                              
-rw-r--r-- 1 root root 138 Dec  5  2021 /usr/lib/systemd/system/dpkg-db-backup.timer
-rw-r--r-- 1 root root 147 Dec  5  2021 /usr/lib/systemd/system/dpkg-db-backup.service
-rwxr-xr-x 1 root root 1086 Oct 31  2021 /usr/src/linux-headers-5.15.0-52/tools/testing/selftests/net/tcp_fastopen_backup_key.sh                                                                                                        
-rwxr-xr-x 1 root root 1086 Oct 31  2021 /usr/src/linux-headers-5.15.0-25/tools/testing/selftests/net/tcp_fastopen_backup_key.sh                                                                                                        
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 11849 Nov  1  2022 /usr/share/info/dir.old
-rw-r--r-- 1 root root 2747 Feb 16  2022 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 416107 Dec 21  2020 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 819, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 3, database pages 7, cookie 0x5, schema 4, UTF-8, version-valid-for 3
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 5

 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                     
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)                                           
                                                                                                                    
╔══════════╣ Web files?(output limit)
                                                                                                                    
╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 dev dev 220 Nov  7  2022 /home/dev/.bash_logout                                                        
-rw-r--r-- 1 landscape landscape 0 Apr 21  2022 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 220 Jan  6  2022 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 0 Nov  7  2022 /etc/.java/.systemPrefs/.systemRootModFile
-rw-r--r-- 1 root root 0 Nov  7  2022 /etc/.java/.systemPrefs/.system.lock
-rw------- 1 root root 0 Apr 21  2022 /etc/.pwd.lock
-rw------- 1 root root 0 Feb 20  2025 /run/snapd/lock/.lock
-rw-r--r-- 1 root root 20 Feb 20  2025 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Jan 13 00:28 /run/cloud-init/.ds-identify.result
-rw------- 1 root root 0 Mar 18  2022 /snap/core20/1405/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1405/etc/skel/.bash_logout
-rw------- 1 root root 0 Sep 19  2022 /snap/core20/1634/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1634/etc/skel/.bash_logout
-rw-r--r-- 1 root root 1840 Jul 22  2022 /usr/lib/jvm/.java-1.18.0-openjdk-amd64.jinfo
-rw-r--r-- 1 root root 2047 Jul 22  2022 /usr/lib/jvm/.java-1.11.0-openjdk-amd64.jinfo

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                                                                                                   
-rw------- 1 dev dev 32768 Jan 13 01:48 /tmp/hsperfdata_dev/841                                                     
-rw-r--r-- 1 root root 81920 Jan 13 00:28 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 0 Jan 13 00:28 /var/backups/dpkg.arch.0

╔══════════╣ Searching passwords in history files
                                                                                                                    
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password                                                                                          
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-310.pyc
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-310.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-310.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-310.pyc
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                    
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                    
╔══════════╣ Searching passwords inside logs (limit 70)
                                                                                                                    
╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars
_=/bin/bash                                                                                                         
HOME=/home/dev
LANG=en_US.UTF-8
LESSCLOSE=/usr/bin/lesspipe %s %s
LESSOPEN=| /usr/bin/lesspipe %s
_=./linpeas.sh
LOGNAME=dev
OLDPWD=/
PWD=/
PWD=/home/dev
SHELL=/bin/bash
SHLVL=0
SHLVL=1
SHLVL=2
SHLVL=3
USER=dev
_=/usr/bin/dd
_=/usr/bin/grep
_=/usr/bin/java
_=/usr/bin/script
_=/usr/bin/xxd


                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                  
                                ╚════════════════╝                                                                  
Regexes to search for API keys aren't activated, use param '-r' 
