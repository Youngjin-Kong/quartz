@echo off
reg save HKLM\SAM "C:\Backups\SAM.bak" /y
reg save HKLM\SECURITY "C:\Backups\SECURITY.bak" /y
reg save HKLM\SYSTEM "C:\Backups\SYSTEM.bak" /y

