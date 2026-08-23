```bash
PS C:\Users\Administrator\Desktop> .\winPEASx64.exe
.\winPEASx64.exe
 [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help
ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD

               ((((((((((((((((((((((((((((((((
        (((((((((((((((((((((((((((((((((((((((((((
      ((((((((((((((**********/##########(((((((((((((
    ((((((((((((********************/#######(((((((((((
    ((((((((******************/@@@@@/****######((((((((((
    ((((((********************@@@@@@@@@@/***,####((((((((((
    (((((********************/@@@@@%@@@@/********##(((((((((
    (((############*********/%@@@@@@@@@/************((((((((
    ((##################(/******/@@@@@/***************((((((
    ((#########################(/**********************(((((
    ((##############################(/*****************(((((
    ((###################################(/************(((((
    ((#######################################(*********(((((
    ((#######(,.***.,(###################(..***.*******(((((
    ((#######*(#####((##################((######/(*****(((((
    ((###################(/***********(##############()(((((
    (((#####################/*******(################)((((((
    ((((############################################)((((((
    (((((##########################################)(((((((
    ((((((########################################)(((((((
    ((((((((####################################)((((((((
    (((((((((#################################)(((((((((
        ((((((((((##########################)(((((((((
              ((((((((((((((((((((((((((((((((((((((
                 ((((((((((((((((((((((((((((((

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own devices and/or with the device owner's permission.

  WinPEAS-ng by @hacktricks_live

       /---------------------------------------------------------------------------------\
       |                             Do you like PEASS?                                  |
       |---------------------------------------------------------------------------------|
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |
       |         Follow on Twitter         :     @hacktricks_live                        |
       |         Respect on HTB            :     SirBroccoli                             |
       |---------------------------------------------------------------------------------|
       |                                 Thank you!                                      |
       \---------------------------------------------------------------------------------/

  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

 You can find a Windows local PE Checklist here: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
   Creating Dynamic lists, this could take a while, please wait...
   - Loading sensitive_files yaml definitions file...
   - Loading regexes yaml definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
   - Creating active users list (local only)...
   - Creating disabled users list...
   - Admin users list...

   - Creating AppLocker bypass list...
   - Creating files/directories list for search...


�����������������������������������͹ System Information �������������������������������������

����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits
    OS Name: Microsoft Windows 11 Pro
    OS Version: Intel64 Family 6 Model 106 Stepping 6 GenuineIntel ~2900 Mhz
    System Type: x64-based PC
    Hostname: WS26
    Domain Name: oscp.exam
    ProductName: Windows 10 Pro
    EditionID: Professional
    ReleaseId: 2009
    BuildBranch: co_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 4
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: True
    Current Time: 8/22/2026 5:03:16 PM
    HighIntegrity: True
    PartOfDomain: True
    Hotfixes: KB5030650 (2/18/2026), KB5030842 (2/18/2026), KB5011048 (2/18/2026), KB5031358 (2/18/2026), KB5031591 (2/17/2026),


����������͹ Showing All Microsoft Updates
   HotFix ID                :   KB2267602
   Installed At (UTC)       :   2/20/2026 7:26:24 PM
   Title                    :   Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.445.155.0) - Current Channel (Broad)
   Client Application ID    :   Windows Defender
   Description              :   Install this update to revise the files that are used to detect viruses, spyware, and other potentially unwanted software. Once you have installed this item, it cannot be removed.

   =================================================================================================

   HotFix ID                :   KB2267602
   Installed At (UTC)       :   2/19/2026 2:48:51 AM
   Title                    :   Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.445.126.0) - Current Channel (Broad)
   Client Application ID    :   Windows Defender
   Description              :   Install this update to revise the files that are used to detect viruses, spyware, and other potentially unwanted software. Once you have installed this item, it cannot be removed.

   =================================================================================================


����������͹ System Last Shutdown Date/time (from Registry)

    Last Shutdown Date/time        :    5/1/2026 12:17:46 PM

����������͹ User Environment Variables
� Check for some passwords or keys in the env variables
    COMPUTERNAME: WS26
    PUBLIC: C:\Users\Public
    LOCALAPPDATA: C:\Windows\system32\config\systemprofile\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 6
    ProgramFiles: C:\Program Files
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
    USERPROFILE: C:\Windows\system32\config\systemprofile
    SystemRoot: C:\Windows
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    AP_PARENT_PID: 1976
    ProgramData: C:\ProgramData
    PROCESSOR_REVISION: 6a06
    USERNAME: WS26$
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 106 Stepping 6, GenuineIntel
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Windows\TEMP
    NUMBER_OF_PROCESSORS: 4
    APPDATA: C:\Windows\system32\config\systemprofile\AppData\Roaming
    TMP: C:\Windows\TEMP
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: OSCP

����������͹ System Environment Variables
� Check for some passwords or keys in the env variables
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 4
    PROCESSOR_LEVEL: 6
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 106 Stepping 6, GenuineIntel
    PROCESSOR_REVISION: 6a06

����������͹ Audit Settings
� Check what is being logged
    Not Found

����������͹ Audit Policy Settings - Classic & Advanced

����������͹ WEF Settings
� Windows Event Forwarding, is interesting to know were are sent the logs
    Not Found

����������͹ LAPS Settings
� If installed, local administrator password is changed frequently and is restricted by ACL
    LAPS Enabled: LAPS not installed

����������͹ Wdigest
� If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wdigest
    Wdigest is not enabled

����������͹ LSA Protection
� If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#lsa-protection
    LSA Protection is not enabled

����������͹ Credentials Guard
� If enabled, a driver is needed to read LSASS memory https://book.hacktricks.wiki/windows-hardening/stealing-credentials/credentials-protections#credentials-guard
    CredentialGuard is not enabled
    Virtualization Based Security Status:      Not enabled
    Configured:                                False
    Running:                                   False

����������͹ Cached Creds
� If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#cached-credentials
    cachedlogonscount is 10

����������͹ Enumerating saved credentials in Registry (CurrentPass)

����������͹ AV Information
    Some AV was detected, search for bypasses
    Name: Windows Defender
    ProductEXE: windowsdefender://
    pathToSignedReportingExe: %ProgramFiles%\Windows Defender\MsMpeng.exe

����������͹ Windows Defender configuration
  Local Settings
  Group Policy Settings

����������͹ UAC Status
� If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#from-administrator-medium-to-high-integrity-level--uac-bypasss
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy:
    FilterAdministratorToken:
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
      [-] Only the RID-500 local admin account can be used for lateral movement.

����������͹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.22000.1
    PowerShell Core Version:
    Transcription Settings:
    Module Logging Settings:
    Scriptblock Logging Settings:
    PS history file:
    PS history size:

����������͹ Enumerating PowerShell Session Settings using the registry
    Name                                   Microsoft.PowerShell
      BUILTIN\Administrators               AccessAllowed
      NT AUTHORITY\INTERACTIVE             AccessAllowed
      BUILTIN\Remote Management Users      AccessAllowed
   =================================================================================================

    Name                                   Microsoft.PowerShell.Workflow
      BUILTIN\Administrators               AccessAllowed
      BUILTIN\Remote Management Users      AccessAllowed
   =================================================================================================

    Name                                   Microsoft.PowerShell32
      BUILTIN\Administrators               AccessAllowed
      NT AUTHORITY\INTERACTIVE             AccessAllowed
      BUILTIN\Remote Management Users      AccessAllowed
   =================================================================================================


����������͹ PS default transcripts history
� Read the PS history inside these files (if any)

����������͹ HKCU Internet Settings
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    IE5_UA_Backup_Flag: 5.0
    ZonesSecurityUpgrade: System.Byte[]
    EnableNegotiate: 1
    ProxyEnable: 0
    MigrateProxy: 1

����������͹ HKLM Internet Settings
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

����������͹ Drives Information
� Remember that you should search more info inside the other drives
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 15 GB)(Permissions: Authenticated Users [Allow: AppendData/CreateDirectories], SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    D:\ (Type: CDRom)

����������͹ Checking WSUS
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus
    Not Found

����������͹ Checking KrbRelayUp
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#krbrelayup
  The system is inside a domain (OSCP) so it could be vulnerable.
� You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges

����������͹ Checking If Inside Container
� If the binary cexecsvc.exe or associated service exists, you are inside Docker
You are NOT inside a container

����������͹ Checking AlwaysInstallElevated
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated
    AlwaysInstallElevated isn't available

����������͹ Enumerate LSA settings - auth packages included

    auditbasedirectories                 :       0
    auditbaseobjects                     :       0
    Authentication Packages              :       msv1_0
    Bounds                               :       00-30-00-00-00-20-00-00
    crashonauditfail                     :       0
    fullprivilegeauditing                :       00
    LimitBlankPasswordUse                :       1
    NoLmHash                             :       1
    Notification Packages                :       scecli
    Security Packages                    :       ""
    LsaPid                               :       808
    LsaCfgFlagsDefault                   :       0
    SecureBoot                           :       1
    ProductType                          :       6
    disabledomaincreds                   :       0
    everyoneincludesanonymous            :       0
    forceguest                           :       0
    restrictanonymous                    :       0
    restrictanonymoussam                 :       1

����������͹ Enumerating NTLM Settings
  LanmanCompatibilityLevel    :  (Send NTLMv2 response only - Win7+ default)


  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)


  NTLM Auditing and Restrictions
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      :

����������͹ Display Local Group Policy settings - local users/machine
   Type             :     machine
   Display Name     :     Default Domain Policy
   Name             :     {31B2F340-016D-11D2-945F-00C04FB984F9}
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]
   File Sys Path    :     C:\Windows\system32\GroupPolicy\DataStore\0\sysvol\oscp.exam\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine
   Link             :     LDAP://DC=oscp,DC=exam
   GPO Link         :     Domain
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     user
   Display Name     :     Local Group Policy
   Name             :     Local Group Policy
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F73-3407-48AE-BA88-E8213C6761F1}]
   File Sys Path    :     C:\Windows\System32\GroupPolicy\User
   Link             :     Local
   GPO Link         :     Local Machine
   Options          :     All Sections Enabled

   =================================================================================================


����������͹ Potential GPO abuse vectors (applied domain GPOs writable by current user)
  [-] Controlled exception, info about OSCP\SYSTEM not found
    No obvious GPO abuse via writable SYSVOL paths or GPCO membership detected.

����������͹ Checking AppLocker effective policy
   AppLockerPolicy version: 1
   listing rules:



����������͹ Enumerating Printers (WMI)

����������͹ Enumerating Named Pipes
  Name                                                                                                 CurrentUserPerms                                                       Sddl

  atsvc                                                                                                Everyone [Allow: WriteData/CreateFiles]                                O:SYG:SYD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-4125092361-1567024937-842823819-2091237918-836075745)

  crashpad_11152_KCDNGRNQVXBFLPVF                                                                      SYSTEM [Allow: AllAccess]                                              O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1010576050-2316036354-870063271-1120)(A;;0x12019f;;;AC)

  crashpad_9404_WBTXMUETKHDKHXGD                                                                       SYSTEM [Allow: AllAccess]                                              O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1010576050-2316036354-870063271-1120)(A;;0x12019f;;;AC)

  crashpad_9736_JRGGLVNRQHWLOYYS                                                                       SYSTEM [Allow: AllAccess]                                              O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1010576050-2316036354-870063271-1120)(A;;0x12019f;;;AC)

  Ctx_WinStation_API_service                                                                           Everyone [Allow: WriteData/CreateFiles]                                O:NSG:NSD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-446051430-1559341753-4161941529-1950928533-810483104)

  epmapper                                                                                             Everyone [Allow: WriteData/CreateFiles]                                O:NSG:NSD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-521322694-906040134-3864710659-1525148216-3451224162)(A;;0x12019b;;;AC)

  eventlog                                                                                             Everyone [Allow: WriteData/CreateFiles]                                O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)

  InitShutdown                                                                                         Everyone [Allow: WriteData/CreateFiles], Administrators [Allow: AllAccess] O:BAG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;BA)

  LOCAL\mojo.external_task_manager_v2_11152                                                            SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]           O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)

  LOCAL\S-1-5-5-0-8274554-Teams-2.0-instance-pipe                                                      SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]           O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;FR;;;WD)(A;;FR;;;AN)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1010576050-2316036354-870063271-1120)

  lsass                                                                                                Everyone [Allow: WriteData/CreateFiles], Administrators [Allow: AllAccess] O:BAG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;BA)(A;;0x12019b;;;S-1-15-3-8)

  LSM_API_service                                                                                      Everyone [Allow: WriteData/CreateFiles]                                O:SYG:SYD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-1230977110-1477712667-2747199032-477530733-939374687)

  MsFteWds                                                                                             Authenticated Users [Allow: WriteData/CreateFiles], SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles] O:SYG:SYD:(A;;0x12019b;;;AU)(A;;0x12019f;;;SY)(A;;0x12019b;;;BA)(A;;0x12019b;;;BG)(A;;0x12019b;;;S-1-15-3-128907917-1049808183-3772720920-2589851895-2273257875-2082631859-2896883434)(A;;0x12019b;;;S-1-15-3-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742)(A;;0x12019b;;;S-1-15-3-1024-724741592-1210917904-489960769-637019204-3345707629-3097053430-1727148295-85063603)

  ntsvcs                                                                                               Everyone [Allow: WriteData/CreateFiles], Administrators [Allow: AllAccess] O:BAG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;BA)

  PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER                                                               SYSTEM [Allow: AllAccess]                                              O:SYG:SYD:(A;;FA;;;SY)(A;;0x12019b;;;LS)(A;;0x12019b;;;NS)

  PSHost.134319053874763596.4396.DefaultAppDomain.wsmprovhost                                          Administrators [Allow: TakeOwnership]                                  O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;0x1f019f;;;BA)(A;;0x1f019f;;;S-1-5-21-1010576050-2316036354-870063271-1120)

  PSHost.134319163004191210.680.DefaultAppDomain.powershell                                            Administrators [Allow: TakeOwnership]                                  O:BAG:SYD:(A;;0x1f019f;;;BA)

  PSHost.134319164575143902.6224.DefaultAppDomain.powershell                                           Administrators [Allow: TakeOwnership]                                  O:BAG:SYD:(A;;0x1f019f;;;BA)

  PSHost.134319166637670467.5416.DefaultAppDomain.powershell                                           Administrators [Allow: TakeOwnership]                                  O:BAG:SYD:(A;;0x1f019f;;;BA)

  PSHost.134319167162795573.9096.DefaultAppDomain.wsmprovhost                                          Administrators [Allow: TakeOwnership]                                  O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;0x1f019f;;;BA)(A;;0x1f019f;;;S-1-5-21-1010576050-2316036354-870063271-1120)

  scerpc                                                                                               Everyone [Allow: WriteData/CreateFiles], Administrators [Allow: AllAccess] O:BAG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;BA)

  SearchTextHarvester                                                                                  SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]           O:SYG:SYD:P(D;;FA;;;NU)(D;;FA;;;BG)(A;;FR;;;IU)(A;;FA;;;SY)(A;;FA;;;BA)

  SessEnvPublicRpc                                                                                     Everyone [Allow: WriteData/CreateFiles]                                O:SYG:SYD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-4022436659-1090538466-1613889075-870485073-3428993833)

  srvsvc                                                                                               Everyone [Allow: WriteData/CreateFiles], SYSTEM [Allow: AllAccess]     O:SYG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)

  TermSrv_API_service                                                                                  Everyone [Allow: WriteData/CreateFiles]                                O:NSG:NSD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-446051430-1559341753-4161941529-1950928533-810483104)

  trkwks                                                                                               Everyone [Allow: WriteData/CreateFiles]                                O:SYG:SYD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-768763963-4214222998-2156221936-2953597973-713500239)

  vgauth-service                                                                                       Everyone [Allow: WriteData/CreateFiles], SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess] O:BAG:SYD:P(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)

  W32TIME_ALT                                                                                          Everyone [Allow: WriteData/CreateFiles]                                O:LSG:LSD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-4267341169-2882910712-659946508-2704364837-2204554466)

  WidgetsCommandPipe                                                                                   SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]           O:S-1-5-21-1010576050-2316036354-870063271-1120G:DUD:(A;;FR;;;WD)(A;;FR;;;AN)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1010576050-2316036354-870063271-1120)

  Winsock2\CatalogChangeListener-328-0                                                                 SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles] O:BAG:SYD:(D;;FW;;;NU)(A;;0x120196;;;SY)(A;;0x120196;;;BA)

  Winsock2\CatalogChangeListener-840-0                                                                 SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles] O:LSG:LSD:(D;;FW;;;NU)(A;;0x120196;;;SY)(A;;0x120196;;;BA)

  wkssvc                                                                                               Everyone [Allow: WriteData/CreateFiles], SYSTEM [Allow: AllAccess]     O:NSG:NSD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)(A;;FA;;;NS)


����������͹ Enumerating AMSI registered providers
    Provider:       {2781761E-28E0-4109-99FE-B9D127C57AFE}
    Path:           "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpOav.dll"

   =================================================================================================

    Provider:       {38CEFD7B-0E35-4DE5-8BE4-000A5D8557C9}
    Path:           C:\Windows\system32\vsepamsi_x64.dll

   =================================================================================================


����������͹ Enumerating Sysmon configuration
      Installed:                False
      Hashing Algorithm:        Not Defined
      Options:                  Not Defined
      Rules:

   =================================================================================================


����������͹ Enumerating Sysmon process creation logs (1)
      Unable to query Sysmon event logs, Sysmon likely not installed.

����������͹ Installed .NET versions

  CLR Versions
   4.0.30319

  .NET Versions
   4.8.09037

  .NET & AMSI (Anti-Malware Scan Interface) support
      .NET version supports AMSI     : True
      OS supports AMSI               : True
        [!] The highest .NET version is enrolled in AMSI!


�����������������������������������͹ Interesting Events information �������������������������������������

����������͹ Printing Explicit Credential Events (4648) for last 30 days - A process logged on using plaintext credentials

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 9:01:08 PM
  IP Address         :         192.168.49.104
  Process            :         C:\Windows\System32\svchost.exe
  Target User        :         r.andrews
  Target Domain      :         OSCP

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:32 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:31 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:30 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:30 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:30 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:28 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:27 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:27 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:24 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:23 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================

  Subject User       :         WS26$
  Subject Domain     :         OSCP
  Created (UTC)      :         8/22/2026 2:52:23 PM
  IP Address         :         -
  Process            :         C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  Target User        :         Administrator
  Target Domain      :         WS26

   =================================================================================================


����������͹ Printing Account Logon Events (4624) for the last 10 days.

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 11:58:35 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 11:32:53 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 11:31:00 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 11:30:11 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:10:48 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:10:28 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:08:48 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:06:53 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:04:33 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:04:12 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:03:38 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:01:53 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 10:01:09 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:38:22 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:37:53 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:27:55 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:26:48 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:19:25 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:18:40 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:17:55 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:17:29 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:15:21 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:11:56 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:09:12 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:01:40 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 9:01:08 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       Negotiate
  Lm Package                   :
  Logon Type                   :       RemoteInteractive
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:01:04 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 9:00:29 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 8:54:17 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 8:52:16 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 8:50:39 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 8:49:47 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:37:58 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:30:47 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:27:35 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:24:11 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:23:44 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:23:09 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:22:42 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:22:11 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:20:53 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:20:07 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:18:46 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:18:13 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:15:51 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:14:37 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:13:37 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:10:30 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       -
  Subject Domain Name          :       -
  Created (Utc)                :       8/22/2026 3:10:21 PM
  IP Address                   :       192.168.49.104
  Authentication Package       :       NTLM
  Lm Package                   :       NTLM V2
  Logon Type                   :       Network
  Target User Name             :       r.andrews
  Target Domain Name           :       OSCP
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:32 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:31 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:30 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:30 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:30 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:28 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:27 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:27 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:24 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:23 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  Subject User Name            :       WS26$
  Subject Domain Name          :       OSCP
  Created (Utc)                :       8/22/2026 2:52:23 PM
  IP Address                   :       -
  Authentication Package       :       MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
  Lm Package                   :
  Logon Type                   :       Batch
  Target User Name             :       Administrator
  Target Domain Name           :       WS26
  Target Outbound User Name    :       -
  Target Outbound Domain Name  :       -

   =================================================================================================

  NTLM relay might be possible - other users authenticate to this machine using NTLM!

  Accounts authenticate to this machine using NTLM v2!
  You can obtain NetNTLMv2 for these accounts by sniffing NTLM challenge/responses.
  You can then try and crack their passwords.

    OSCP\r.andrews

����������͹ Process creation events - searching logs (EID 4688) for sensitive data.


����������͹ PowerShell events - script block logs (EID 4104) - searching for sensitive data.


����������͹ Displaying Power off/on events for last 5 days



�����������������������������������͹ Users Information �������������������������������������

����������͹ Users
� Check if you have some admin equivalent privileges https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups
  Current user: SYSTEM
  Current groups: Administrators, Everyone, Authenticated Users
   =================================================================================================

    WS26\4leaf
        |->Groups: Users
        |->Password: CanChange-Expi-Req

    WS26\Administrator: Built-in account for administering the computer/domain
        |->Groups: Administrators
        |->Password: CanChange-NotExpi-Req

    WS26\DefaultAccount(Disabled): A user account managed by the system.
        |->Groups: System Managed Accounts Group
        |->Password: CanChange-NotExpi-NotReq

    WS26\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Guests
        |->Password: NotChange-NotExpi-NotReq

    WS26\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
        |->Password: CanChange-NotExpi-Req


����������͹ Current User Idle Time
   Current User   :     NT AUTHORITY\SYSTEM
   Idle Time      :     09h:17m:05s:062ms

����������͹ Display Tenant information (DsRegCmd.exe /status)
   Tenant is NOT Azure AD Joined.

����������͹ Current Token privileges
� Check if you can escalate privilege using some enabled token https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#token-manipulation
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeLockMemoryPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeTcbPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeSecurityPrivilege: DISABLED
    SeTakeOwnershipPrivilege: DISABLED
    SeLoadDriverPrivilege: DISABLED
    SeSystemProfilePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeSystemtimePrivilege: DISABLED
    SeProfileSingleProcessPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseBasePriorityPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreatePagefilePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreatePermanentPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeBackupPrivilege: DISABLED
    SeRestorePrivilege: DISABLED
    SeShutdownPrivilege: DISABLED
    SeDebugPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeAuditPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeSystemEnvironmentPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeUndockPrivilege: DISABLED
    SeManageVolumePrivilege: DISABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeTimeZonePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateSymbolicLinkPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeDelegateSessionUserImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

����������͹ Clipboard text

����������͹ Logged users
    OSCP\r.andrews

����������͹ Display information about local users
   Computer Name           :   WS26
   User Name               :   4leaf
   User Id                 :   1004
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   8/22/2026 4:49:47 PM

   =================================================================================================

   Computer Name           :   WS26
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   8/22/2026 7:52:32 AM
   Logons Count            :   40
   Password Last Set       :   2/18/2026 10:18:52 AM

   =================================================================================================

   Computer Name           :   WS26
   User Name               :   DefaultAccount
   User Id                 :   503
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   A user account managed by the system.
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   WS26
   User Name               :   Guest
   User Id                 :   501
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   Built-in account for guest access to the computer/domain
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   WS26
   User Name               :   WDAGUtilityAccount
   User Id                 :   504
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   A user account managed and used by the system for Windows Defender Application Guard scenarios.
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   2/11/2026 11:36:31 AM

   =================================================================================================


����������͹ RDP Sessions
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    2         RDP-Tcp#0      r.andrews      OSCP                     Active    192.168.49.104

����������͹ Ever logged users
    WS26\Administrator
    OSCP\r.andrews

����������͹ Home folders found
    C:\Users\Administrator : SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    C:\Users\All Users : SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    C:\Users\Default : SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    C:\Users\Default User : SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    C:\Users\Public : SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    C:\Users\r.andrews : SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]

����������͹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  offsec

����������͹ Password Policies
� Check for a possible brute-force
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================

    Domain: WS26
    SID: S-1-5-21-3669261096-1585953307-1535951119
    MaxPasswordAge: 42.00:00:00
    MinPasswordAge: 1.00:00:00
    MinPasswordLength: 7
    PasswordHistoryLength: 24
    PasswordProperties: 0
   =================================================================================================


����������͹ Print Logon Sessions
    Method:                       LSA
    Logon Server:                 DC20
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     52246441
    Logon Time:                   8/22/2026 11:58:35 PM
    Logon Type:                   Network
    Start Time:
    Domain:                       OSCP
    Authentication Package:       NTLM
    Start Time:
    User Name:                    r.andrews
    User Principal Name:          r.andrews@oscp.exam
    User SID:                     S-1-5-21-1010576050-2316036354-870063271-1120

   =================================================================================================

    Method:                       LSA
    Logon Server:                 DC20
    Logon Server Dns Domain:      OSCP.EXAM
    Logon Id:                     8275776
    Logon Time:                   8/22/2026 9:01:08 PM
    Logon Type:                   RemoteInteractive
    Start Time:
    Domain:                       OSCP
    Authentication Package:       Kerberos
    Start Time:
    User Name:                    r.andrews
    User Principal Name:          r.andrews@OSCP.EXAM
    User SID:                     S-1-5-21-1010576050-2316036354-870063271-1120

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:
    Logon Id:                     8250499
    Logon Time:                   8/22/2026 9:01:07 PM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Window Manager
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    DWM-2
    User Principal Name:
    User SID:                     S-1-5-90-0-2

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:
    Logon Id:                     8250457
    Logon Time:                   8/22/2026 9:01:07 PM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Window Manager
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    DWM-2
    User Principal Name:
    User SID:                     S-1-5-90-0-2

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     8249268
    Logon Time:                   8/22/2026 9:01:07 PM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Font Driver Host
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    UMFD-2
    User Principal Name:          WS26$@oscp.exam
    User SID:                     S-1-5-96-0-2

   =================================================================================================

    Method:                       LSA
    Logon Server:                 DC20
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     8230857
    Logon Time:                   8/22/2026 9:01:04 PM
    Logon Type:                   Network
    Start Time:
    Domain:                       OSCP
    Authentication Package:       NTLM
    Start Time:
    User Name:                    r.andrews
    User Principal Name:          r.andrews@oscp.exam
    User SID:                     S-1-5-21-1010576050-2316036354-870063271-1120

   =================================================================================================

    Method:                       LSA
    Logon Server:                 DC20
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     8166453
    Logon Time:                   8/22/2026 8:49:46 PM
    Logon Type:                   Network
    Start Time:
    Domain:                       OSCP
    Authentication Package:       NTLM
    Start Time:
    User Name:                    r.andrews
    User Principal Name:          r.andrews@oscp.exam
    User SID:                     S-1-5-21-1010576050-2316036354-870063271-1120

   =================================================================================================

    Method:                       LSA
    Logon Server:                 WS26
    Logon Server Dns Domain:
    Logon Id:                     731830
    Logon Time:                   6/16/2026 2:00:34 AM
    Logon Type:                   Batch
    Start Time:
    Domain:                       WS26
    Authentication Package:       NTLM
    Start Time:
    User Name:                    Administrator
    User Principal Name:
    User SID:                     S-1-5-21-3669261096-1585953307-1535951119-500

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:
    Logon Id:                     997
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   Service
    Start Time:
    Domain:                       NT AUTHORITY
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    LOCAL SERVICE
    User Principal Name:
    User SID:                     S-1-5-19

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:
    Logon Id:                     71149
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Window Manager
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    DWM-1
    User Principal Name:
    User SID:                     S-1-5-90-0-1

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:
    Logon Id:                     71131
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Window Manager
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    DWM-1
    User Principal Name:
    User SID:                     S-1-5-90-0-1

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:
    Logon Id:                     996
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   Service
    Start Time:
    Domain:                       OSCP
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    WS26$
    User Principal Name:
    User SID:                     S-1-5-20

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     40985
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Font Driver Host
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    UMFD-0
    User Principal Name:          WS26$@oscp.exam
    User SID:                     S-1-5-96-0-0

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     40947
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   Interactive
    Start Time:
    Domain:                       Font Driver Host
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    UMFD-1
    User Principal Name:          WS26$@oscp.exam
    User SID:                     S-1-5-96-0-1

   =================================================================================================

    Method:                       LSA
    Logon Server:
    Logon Server Dns Domain:      oscp.exam
    Logon Id:                     999
    Logon Time:                   6/16/2026 1:55:18 AM
    Logon Type:                   0
    Start Time:
    Domain:                       OSCP
    Authentication Package:       Negotiate
    Start Time:
    User Name:                    WS26$
    User Principal Name:          WS26$@oscp.exam
    User SID:                     S-1-5-18

   =================================================================================================



�����������������������������������͹ Processes Information �������������������������������������

����������͹ Interesting Processes -non Microsoft-
� Check if any interesting processes for memory dump or if you could overwrite some binary running https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes
    sihost(372)[C:\Windows\system32\sihost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: sihost.exe
   =================================================================================================

    svchost(2152)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
   =================================================================================================

    msedge(5164)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --always-read-main-dll --metrics-shmem-handle=2012,i,328174325501051265,8746041194672936049,524288 --field-trial-handle=1992,i,16666200583148690226,6383716170926131157,262144 --variations-seed-version --trace-process-track-uuid=3190708989122997041 --mojo-platform-channel-handle=2128 /prefetch:11
   =================================================================================================

    svchost(3436)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInputService
   =================================================================================================

    conhost(8176)[C:\Windows\system32\conhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    WmiPrvSE(8052)[C:\Windows\system32\wbem\wmiprvse.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32\wbem (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\wbem\wmiprvse.exe
   =================================================================================================

    conhost(11108)[C:\Windows\system32\conhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    svchost(6436)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k netsvcs -p -s BITS
   =================================================================================================

    msedge(3848)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=gpu-process --gpu-preferences=SAAAAAAAAADgAAAEAAAAAAAAAAAAAGAAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --always-read-main-dll --metrics-shmem-handle=1692,i,11118648167513017680,14584710037039936122,262144 --field-trial-handle=1992,i,16666200583148690226,6383716170926131157,262144 --variations-seed-version --trace-process-track-uuid=3190708988185955192 --mojo-platform-channel-handle=1988 /prefetch:2
   =================================================================================================

    conhost(828)[C:\Windows\system32\conhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    svchost(396)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -s ScDeviceEnum
   =================================================================================================

    svchost(1252)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s Netman
   =================================================================================================

    svchost(2112)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
   =================================================================================================

    svchost(1244)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalService -s W32Time
   =================================================================================================

    dllhost(9860)[C:\Windows\system32\DllHost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
   =================================================================================================

    lsass(808)[C:\Windows\system32\lsass.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\lsass.exe
   =================================================================================================

    msedge(7272)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --disable-gpu-compositing --video-capture-use-gpu-memory-buffer --lang=en-US --js-flags --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --renderer-client-id=26 --time-ticks-at-unix-epoch=-1787410010017691 --launch-time-ticks=27144612592 --always-read-main-dll --metrics-shmem-handle=7640,i,10894022041557411638,14607556737799864235,2097152 --field-trial-handle=1992,i,16666200583148690226,6383716170926131157,262144 --variations-seed-version --trace-process-track-uuid=3190709010674959568 --mojo-platform-channel-handle=7296 /prefetch:1
   =================================================================================================

    msedgewebview2(3392)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=renderer --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView" --webview-exe-name=Widgets.exe --webview-exe-version=526.1202.10.0 --embedded-browser-webview=1 --video-capture-use-gpu-memory-buffer --lang=en-US --js-flags=--expose-gc --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --renderer-client-id=5 --time-ticks-at-unix-epoch=-1787410010017690 --launch-time-ticks=22779235035 --always-read-main-dll --metrics-shmem-handle=3980,i,7387351465139002230,17701897443708029712,2097152 --field-trial-handle=1896,i,11095452446163939330,12735135118917262718,262144 --variations-seed-version --trace-process-track-uuid=3190708990997080739 --mojo-platform-channel-handle=3944 /prefetch:1
   =================================================================================================

    svchost(1236)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalService -p -s nsi
   =================================================================================================

    svchost(5976)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p -s SSDPSRV
   =================================================================================================

    msedgewebview2(8992)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=crashpad-handler --user-data-dir=C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView /prefetch:4 --monitor-self-annotation=ptype=crashpad-handler --database=C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Crashpad --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=144.0.7559.133 "--annotation=exe=C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --annotation=plat=Win64 "--annotation=prod=Edge WebView2" --annotation=ver=144.0.3719.115 --initial-client-data=0x160,0x164,0x168,0x13c,0x94,0x7ffd3bea2c98,0x7ffd3bea2ca4,0x7ffd3bea2cb0
   =================================================================================================

    rev(3816)[c:\xampp\rev.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: c:\xampp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: c://xampp//rev.exe
   =================================================================================================

    svchost(3384)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s WpnService
   =================================================================================================

    svchost(2952)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k netsvcs -p -s ShellHWDetection
   =================================================================================================

    svchost(7692)[C:\Windows\system32\svchost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
   =================================================================================================

    msedgewebview2(9412)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView" --webview-exe-name=Widgets.exe --webview-exe-version=526.1202.10.0 --embedded-browser-webview=1 --always-read-main-dll --metrics-shmem-handle=404,i,15377758870113927318,14813457449900077999,524288 --field-trial-handle=1896,i,11095452446163939330,12735135118917262718,262144 --variations-seed-version --trace-process-track-uuid=3190708989122997041 --mojo-platform-channel-handle=2072 /prefetch:11
   =================================================================================================

    cmd(4668)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\SYSTEM32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: cmd
   =================================================================================================

    msedgewebview2(9404)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --embedded-browser-webview=1 --webview-exe-name=msteams.exe --webview-exe-version=25227.501.3887.7600 --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView" --noerrdialogs --embedded-browser-webview-dpi-awareness=2 --autoplay-policy=no-user-gesture-required --disable-background-timer-throttling --disable-features=BreakoutBoxPreferCaptureTimestampInVideoFrames,msWebOOUI --enable-features=msSingleSignOnOSForPrimaryAccountIsShared,msAbydos,msAbydosGestureSupport,msAbydosHandwritingAttr,msWebView2EnableDraggableRegions,msWebView2SetUserAgentOverrideOnIframes,msWebView2TerminateServiceWorkerWhenIdleIgnoringCdpSessions --js-flags=--stack-trace-limit=50 --lang=en-US --mojo-named-platform-channel-pipe=7284.6752.1145080670947824671
   =================================================================================================

    svchost(2076)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -s CertPropSvc
   =================================================================================================

    OneDrive(4660)[C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\OneDrive.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line:  /setautostart /background
   =================================================================================================

    WmiPrvSE(4224)[C:\Windows\system32\wbem\wmiprvse.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32\wbem (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\wbem\wmiprvse.exe
   =================================================================================================

    msteams(7284)[C:\Program Files\WindowsApps\MicrosoftTeams_25227.501.3887.7600_x64__8wekyb3d8bbwe\msteams.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files\WindowsApps\MicrosoftTeams_25227.501.3887.7600_x64__8wekyb3d8bbwe (SYSTEM [Allow: AllAccess])
    Command Line: "C:\Program Files\WindowsApps\MicrosoftTeams_25227.501.3887.7600_x64__8wekyb3d8bbwe\msteams.exe" ms-meetnow:FirstRun?startTime=224680928322&cv=0MbbXqA8CUyYUojSFBVJPA.1.1
   =================================================================================================

    rev(252)[c:\xampp\rev.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: c:\xampp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: c://xampp//rev.exe
   =================================================================================================

    httpd(4212)[C:\xampp\apache\bin\httpd.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\xampp\apache\bin (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache
   =================================================================================================

    msedge(904)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --disable-gpu-compositing --video-capture-use-gpu-memory-buffer --lang=en-US --js-flags --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --renderer-client-id=25 --time-ticks-at-unix-epoch=-1787410010017691 --launch-time-ticks=27047988948 --always-read-main-dll --metrics-shmem-handle=6972,i,13649224078124402776,11717004544624843262,2097152 --field-trial-handle=1992,i,16666200583148690226,6383716170926131157,262144 --variations-seed-version --trace-process-track-uuid=3190709009737917719 --mojo-platform-channel-handle=7004 /prefetch:1
   =================================================================================================

    svchost(3344)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s Winmgmt
   =================================================================================================

    svchost(1188)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s DsmSvc
   =================================================================================================

    msedgewebview2(10664)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=renderer --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView" --webview-exe-name=msteams.exe --webview-exe-version=25227.501.3887.7600 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=2 --autoplay-policy=no-user-gesture-required --disable-background-timer-throttling --video-capture-use-gpu-memory-buffer --lang=en-US --js-flags="--stack-trace-limit=50 --expose-gc" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --renderer-client-id=5 --time-ticks-at-unix-epoch=-1787410010017690 --launch-time-ticks=22487599073 --always-read-main-dll --metrics-shmem-handle=4280,i,17134913127536633779,7999182650026850181,2097152 --field-trial-handle=1812,i,73120744137406923,10506569274468041281,262144 --enable-features=msAbydos,msAbydosGestureSupport,msAbydosHandwritingAttr,msSingleSignOnOSForPrimaryAccountIsShared,msWebView2EnableDraggableRegions,msWebView2SetUserAgentOverrideOnIframes,msWebView2TerminateServiceWorkerWhenIdleIgnoringCdpSessions --disable-features=BreakoutBoxPreferCaptureTimestampInVideoFrames,msWebOOUI --variations-seed-version --trace-process-track-uuid=3190708990997080739 --mojo-platform-channel-handle=4296 /prefetch:1
   =================================================================================================

    dllhost(3928)[C:\Windows\system32\dllhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
   =================================================================================================

    svchost(9008)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s Appinfo
   =================================================================================================

    svchost(2468)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k netsvcs -p -s SessionEnv
   =================================================================================================

    svchost(3760)[C:\Windows\system32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted -p -s PolicyAgent
   =================================================================================================

    SearchHost(6344)[C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" -ServerName:CortanaUI.AppXstmwaab17q5s3y22tp6apqz7a45vwv65.mca
   =================================================================================================

    httpd(1976)[C:\xampp\apache\bin\httpd.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\xampp\apache\bin (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: "C:\xampp\apache\bin\httpd.exe" -k runservice
   =================================================================================================

    msedge(8496)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=storage.mojom.StorageService --lang=en-US --service-sandbox-type=service --always-read-main-dll --metrics-shmem-handle=2272,i,6615100299258549634,1208903193487124057,524288 --field-trial-handle=1992,i,16666200583148690226,6383716170926131157,262144 --variations-seed-version --trace-process-track-uuid=3190708990060038890 --mojo-platform-channel-handle=2604 /prefetch:13
   =================================================================================================

    backgroundTaskHost(10104)[C:\Windows\system32\backgroundTaskHost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\system32\backgroundTaskHost.exe" -ServerName:Global.Accounts.AppXqe94epy97qwa6w3j6w132e8zvcs117nd.mca
   =================================================================================================

    svchost(6900)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s UsoSvc
   =================================================================================================

    svchost(8060)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalService -p -s WdiServiceHost
   =================================================================================================

    svchost(2884)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc
   =================================================================================================

    svchost(1588)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalService -p -s DispBrokerDesktopSvc
   =================================================================================================

    svchost(1156)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalService -p -s LicenseManager
   =================================================================================================

    winlogon(2448)[C:\Windows\system32\winlogon.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: winlogon.exe
   =================================================================================================

    conhost(288)[C:\Windows\system32\conhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    svchost(1148)[C:\Windows\System32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k NetworkService -s TermService
   =================================================================================================

    vmtoolsd(11060)[C:\Program Files\VMware\VMware Tools\vmtoolsd.exe] -- POwn: r.andrews
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files\VMware\VMware Tools (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
   =================================================================================================

    svchost(2528)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k utcsvc -p
   =================================================================================================

    vmtoolsd(3296)[C:\Program Files\VMware\VMware Tools\vmtoolsd.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files\VMware\VMware Tools (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
   =================================================================================================

    msedgewebview2(2864)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=utility --utility-sub-type=storage.mojom.StorageService --lang=en-US --service-sandbox-type=service --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView" --webview-exe-name=Widgets.exe --webview-exe-version=526.1202.10.0 --embedded-browser-webview=1 --always-read-main-dll --metrics-shmem-handle=2272,i,3738078349538588687,7517767818592423535,524288 --field-trial-handle=1896,i,11095452446163939330,12735135118917262718,262144 --variations-seed-version --trace-process-track-uuid=3190708990060038890 --mojo-platform-channel-handle=2516 /prefetch:13
   =================================================================================================

    cmd(3724)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\SYSTEM32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: cmd
   =================================================================================================

    RuntimeBroker(8464)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    RuntimeBroker(5876)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    msdtc(4580)[C:\Windows\System32\msdtc.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\msdtc.exe
   =================================================================================================

    vm3dservice(3284)[C:\Program Files\VMware\VMware Tools\vm3dservice.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files\VMware\VMware Tools (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files\VMware\VMware Tools\vm3dservice.exe"
   =================================================================================================

    svchost(6360)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s TokenBroker
   =================================================================================================

    cmd(9316)[C:\Windows\system32\cmd.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\system32\cmd.exe"
   =================================================================================================

    TrustedInstaller(8020)[C:\Windows\servicing\TrustedInstaller.exe] -- POwn: SYSTEM
    Command Line: C:\Windows\servicing\TrustedInstaller.exe
   =================================================================================================

    svchost(2844)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
   =================================================================================================

    msedgewebview2(9736)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --embedded-browser-webview=1 --webview-exe-name=Widgets.exe --webview-exe-version=526.1202.10.0 --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView" --noerrdialogs --disk-cache-size=52428800 --edge-webview-is-background --lang=en-US --mojo-named-platform-channel-pipe=8300.7120.2439110249446303053
   =================================================================================================

    svchost(2408)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s SENS
   =================================================================================================

    svchost(8872)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s lfsvc
   =================================================================================================

    powershell(680)[C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe] -- POwn: SYSTEM
    Permissions: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\Windows\System32\WindowsPowerShell\v1.0 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: powershell
   =================================================================================================

    svchost(2832)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
   =================================================================================================

    msedgewebview2(5848)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=crashpad-handler --user-data-dir=C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView /prefetch:4 --monitor-self-annotation=ptype=crashpad-handler --database=C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView\Crashpad --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=144.0.7559.133 "--annotation=exe=C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --annotation=plat=Win64 "--annotation=prod=Edge WebView2" --annotation=ver=144.0.3719.115 --initial-client-data=0x164,0x168,0x16c,0x140,0x174,0x7ffd3bea2c98,0x7ffd3bea2ca4,0x7ffd3bea2cb0
   =================================================================================================

    powershell(5416)[C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe] -- POwn: SYSTEM
    Permissions: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\Windows\System32\WindowsPowerShell\v1.0 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: powershell
   =================================================================================================

    svchost(10156)[C:\Windows\system32\svchost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k UnistackSvcGroup
   =================================================================================================

    svchost(5896)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k netsvcs -p
   =================================================================================================

    rev(6680)[c:\xampp\rev.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: c:\xampp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: c://xampp//rev.exe
   =================================================================================================

    MoUsoCoreWorker(8856)[C:\Windows\uus\AMD64\MoUsoCoreWorker.exe] -- POwn: SYSTEM
    Command Line: C:\Windows\uus\AMD64\MoUsoCoreWorker.exe
   =================================================================================================

    winlogon(740)[C:\Windows\system32\winlogon.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: winlogon.exe
   =================================================================================================

    svchost(8848)[C:\Windows\system32\svchost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k UdkSvcGroup -s UdkUserSvc
   =================================================================================================

    VGAuthService(3244)[C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files\VMware\VMware Tools\VMware VGAuth (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess])
    Command Line: "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
   =================================================================================================

    svchost(4536)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k osprivacy -p -s camsvc
   =================================================================================================

    svchost(2460)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s AudioEndpointBuilder
   =================================================================================================

    svchost(1944)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts
   =================================================================================================

    AggregatorHost(3868)[C:\Windows\System32\AggregatorHost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: AggregatorHost.exe
   =================================================================================================

    svchost(6760)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc
   =================================================================================================

    svchost(4524)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k appmodel -p -s StateRepository
   =================================================================================================

    SecurityHealthSystray(10988)[C:\Windows\System32\SecurityHealthSystray.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\System32\SecurityHealthSystray.exe"
   =================================================================================================

    svchost(3228)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TrkWks
   =================================================================================================

    svchost(2796)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k NetSvcs -p -s iphlpsvc
   =================================================================================================

    taskhostw(1500)[C:\Windows\system32\taskhostw.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
   =================================================================================================

    svchost(636)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k DcomLaunch -p -s LSM
   =================================================================================================

    StartMenuExperienceHost(4340)[C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
   =================================================================================================

    svchost(3216)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s LanmanServer
   =================================================================================================

    cmd(6060)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\SYSTEM32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: cmd.exe /s /c "c://xampp//rev.exe"
   =================================================================================================

    winPEASx64(7936)[C:\Users\Administrator\Desktop\winPEASx64.exe] -- POwn: SYSTEM -- isDotNet
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\Administrator\Desktop (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Users\Administrator\Desktop\winPEASx64.exe"
   =================================================================================================

    winPEASx64(2780)[C:\Users\Administrator\Desktop\winPEASx64.exe] -- POwn: SYSTEM -- isDotNet
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\Administrator\Desktop (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Users\Administrator\Desktop\winPEASx64.exe"
   =================================================================================================

    svchost(1484)[C:\Windows\System32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k netprofm -p -s netprofm
   =================================================================================================

    cmd(2776)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\SYSTEM32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: cmd
   =================================================================================================

    Notepad(10964)[C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2510.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2510.14.0_x64__8wekyb3d8bbwe\Notepad (SYSTEM [Allow: AllAccess])
    Command Line: "C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2510.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" /SESSION:YadBcStMXUuXHzLzop+V7wEiYwA6AFwAeABhAG0AcABwAFwAcABoAHAATQB5AEEAZABtAGkAbgBcAGMAbwBuAGYAaQBnAC4AaQBuAGMALgBwAGgAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoAARQRAAAXAQAAlAIAAAAAAAA=
   =================================================================================================

    mysqld(3204)[C:\xampp\mysql\bin\mysqld.exe] -- POwn: SYSTEM
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\xampp\mysql\bin (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
   =================================================================================================

    dllhost(4060)[C:\Windows\system32\DllHost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\DllHost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}
   =================================================================================================

    fontdrvhost(3628)[C:\Windows\system32\fontdrvhost.exe] -- POwn: UMFD-2
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "fontdrvhost.exe"
   =================================================================================================

    FileZillaServer(6212)[c:\xampp\filezillaftp\filezillaserver.exe] -- POwn: r.andrews
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: c:\xampp\filezillaftp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: c:\xampp\filezillaftp\filezillaserver.exe -compat -start
   =================================================================================================

    msedgewebview2(8364)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=gpu-process --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView" --webview-exe-name=Widgets.exe --webview-exe-version=526.1202.10.0 --embedded-browser-webview=1 --gpu-preferences=SAAAAAAAAADgAAAEAAAAAAAAAAAAAGAAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --always-read-main-dll --metrics-shmem-handle=1592,i,3259639399578419811,9151800416674892932,262144 --field-trial-handle=1896,i,11095452446163939330,12735135118917262718,262144 --variations-seed-version --trace-process-track-uuid=3190708988185955192 --mojo-platform-channel-handle=1892 /prefetch:2
   =================================================================================================

    conhost(10948)[C:\Windows\system32\conhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    cmd(7068)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\SYSTEM32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: cmd.exe /s /c "c://xampp//rev.exe"
   =================================================================================================

    cmd(2320)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\SYSTEM32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: cmd.exe /s /c "c://xampp//rev.exe"
   =================================================================================================

    svchost(6628)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s gpsvc
   =================================================================================================

    powershell(6224)[C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe] -- POwn: SYSTEM
    Permissions: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\Windows\System32\WindowsPowerShell\v1.0 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: powershell
   =================================================================================================

    SearchIndexer(1012)[C:\Windows\system32\SearchIndexer.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\SearchIndexer.exe /Embedding
   =================================================================================================

    vm3dservice(3596)[C:\Program Files\VMware\VMware Tools\vm3dservice.exe] -- POwn: SYSTEM
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files\VMware\VMware Tools (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files\VMware\VMware Tools\vm3dservice.exe" -n
   =================================================================================================

    svchost(8336)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s wuauserv
   =================================================================================================

    MoNotificationUx(3156)[C:\Windows\system32\MoNotificationUx.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: %systemroot%\system32\MoNotificationUx.exe /NotificationType Generic_Eos_Important /FormFactor Passive /Timeout 0
   =================================================================================================

    rdpclip(3152)[C:\Windows\System32\rdpclip.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: rdpclip
   =================================================================================================

    conhost(4012)[C:\Windows\system32\conhost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    fontdrvhost(992)[C:\Windows\system32\fontdrvhost.exe] -- POwn: UMFD-1
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "fontdrvhost.exe"
   =================================================================================================

    msedge(11152)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window
   =================================================================================================

    svchost(1420)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s TimeBrokerSvc
   =================================================================================================

    fontdrvhost(984)[C:\Windows\system32\fontdrvhost.exe] -- POwn: UMFD-0
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "fontdrvhost.exe"
   =================================================================================================

    msedge(5724)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=crashpad-handler "--user-data-dir=C:\Users\r.andrews\AppData\Local\Microsoft\Edge\User Data" /prefetch:4 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\r.andrews\AppData\Local\Microsoft\Edge\User Data\Crashpad" --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=145.0.7632.76 "--annotation=exe=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --annotation=plat=Win64 --annotation=prod=Edge --annotation=ver=145.0.3800.65 --initial-client-data=0x25c,0x260,0x264,0x258,0x26c,0x7ffd63820f18,0x7ffd63820f24,0x7ffd63820f30
   =================================================================================================

    svchost(1844)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
   =================================================================================================

    svchost(1412)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService
   =================================================================================================

    dllhost(8732)[C:\Windows\system32\DllHost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}
   =================================================================================================

    Widgets(8300)[C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_526.1202.40.0_x64__cw5n1h2txyewy\Dashboard\Widgets.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_526.1202.40.0_x64__cw5n1h2txyewy\Dashboard (SYSTEM [Allow: AllAccess])
    Command Line: "C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_526.1202.40.0_x64__cw5n1h2txyewy\Dashboard\Widgets.exe" -ServerName:Microsoft.Windows.DashboardServer
   =================================================================================================

    dwm(972)[C:\Windows\system32\dwm.exe] -- POwn: DWM-1
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "dwm.exe"
   =================================================================================================

    svchost(1400)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp
   =================================================================================================

    WUDFHost(2716)[C:\Windows\System32\WUDFHost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\System32\WUDFHost.exe" -HostGUID:{193a1820-d9ac-4997-8c55-be817523f6aa} -IoEventPortName:\UMDFCommunicationPorts\WUDF\HostProcess-895fc2cd-e9b2-42d1-8b49-f3d325b4849d -SystemEventPortName:\UMDFCommunicationPorts\WUDF\HostProcess-f08905e5-085d-4628-9dee-6cb961e1c54f -IoCancelEventPortName:\UMDFCommunicationPorts\WUDF\HostProcess-5a7e810c-e45a-49ea-81f1-a079fc5c897d -NonStateChangingEventPortName:\UMDFCommunicationPorts\WUDF\HostProcess-eb7e9fae-7296-4fe4-9270-0f2b0f9d4469 -LifetimeId:e1ff0852-3c9d-4746-830d-6b99ac2b763c -DeviceGroupId: -HostArg:0
   =================================================================================================

    svchost(7000)[C:\Windows\System32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k NetworkService -p -s WinRM
   =================================================================================================

    explorer(1824)[C:\Windows\Explorer.EXE] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\Explorer.EXE
   =================================================================================================

    svchost(2684)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS
   =================================================================================================

    RuntimeBroker(9148)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    msedgewebview2(10436)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=utility --utility-sub-type=storage.mojom.StorageService --lang=en-US --service-sandbox-type=service --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView" --webview-exe-name=msteams.exe --webview-exe-version=25227.501.3887.7600 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=2 --always-read-main-dll --metrics-shmem-handle=2252,i,11605378826159652689,3772214218526961280,524288 --field-trial-handle=1812,i,73120744137406923,10506569274468041281,262144 --enable-features=msAbydos,msAbydosGestureSupport,msAbydosHandwritingAttr,msSingleSignOnOSForPrimaryAccountIsShared,msWebView2EnableDraggableRegions,msWebView2SetUserAgentOverrideOnIframes,msWebView2TerminateServiceWorkerWhenIdleIgnoringCdpSessions --disable-features=BreakoutBoxPreferCaptureTimestampInVideoFrames,msWebOOUI --variations-seed-version --trace-process-track-uuid=3190708990060038890 --mojo-platform-channel-handle=2480 /prefetch:13
   =================================================================================================

    svchost(2676)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
   =================================================================================================

    svchost(1812)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s UmRdpService
   =================================================================================================

    wsmprovhost(4396)[C:\Windows\system32\wsmprovhost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\wsmprovhost.exe -Embedding
   =================================================================================================

    svchost(2240)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k netsvcs -p -s Themes
   =================================================================================================

    svchost(6548)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalService -p -s CDPSvc
   =================================================================================================

    ctfmon(4392)[C:\Windows\system32\ctfmon.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "ctfmon.exe"
   =================================================================================================

    SearchHost(11028)[C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" -ServerName:FESearchUI.AppXbgxsca4vtwz9gsm457zypgjfyczezg85.mca
   =================================================================================================

    conhost(4384)[C:\Windows\system32\conhost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    LogonUI(4380)[C:\Windows\system32\LogonUI.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "LogonUI.exe" /flags:0x2 /state0:0xa3817855 /state1:0x41c64e6d
   =================================================================================================

    svchost(2224)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s SysMain
   =================================================================================================

    svchost(928)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k DcomLaunch -p
   =================================================================================================

    svchost(2220)[C:\Windows\system32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k NetworkService -p
   =================================================================================================

    TiWorker(8248)[C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.22000.2531_none_8277afecff0305a8\TiWorker.exe] -- POwn: SYSTEM
    Command Line: C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.22000.2531_none_8277afecff0305a8\TiWorker.exe -Embedding
   =================================================================================================

    xampp-control(4364)[C:\xampp\xampp-control.exe] -- POwn: r.andrews
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\xampp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: "C:\xampp\xampp-control.exe"
   =================================================================================================

    xampp-control(9964)[C:\xampp\xampp-control.exe] -- POwn: r.andrews
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\xampp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: "C:\xampp\xampp-control.exe"
   =================================================================================================

    svchost(2204)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalService -p -s EventSystem
   =================================================================================================

    msedgewebview2(10392)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView" --webview-exe-name=msteams.exe --webview-exe-version=25227.501.3887.7600 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=2 --always-read-main-dll --metrics-shmem-handle=2040,i,7485438893189660693,17849745744735583874,524288 --field-trial-handle=1812,i,73120744137406923,10506569274468041281,262144 --enable-features=msAbydos,msAbydosGestureSupport,msAbydosHandwritingAttr,msSingleSignOnOSForPrimaryAccountIsShared,msWebView2EnableDraggableRegions,msWebView2SetUserAgentOverrideOnIframes,msWebView2TerminateServiceWorkerWhenIdleIgnoringCdpSessions --disable-features=BreakoutBoxPreferCaptureTimestampInVideoFrames,msWebOOUI --variations-seed-version --trace-process-track-uuid=3190708989122997041 --mojo-platform-channel-handle=1844 /prefetch:11
   =================================================================================================

    svchost(1164)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p
   =================================================================================================

    wsmprovhost(9096)[C:\Windows\system32\wsmprovhost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\wsmprovhost.exe -Embedding
   =================================================================================================

    MicrosoftEdgeUpdate(6076)[C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe] -- POwn: SYSTEM
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeUpdate (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c
   =================================================================================================

    svchost(2196)[C:\Windows\System32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k NetworkService -p -s LanmanWorkstation
   =================================================================================================

    svchost(2188)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s ProfSvc
   =================================================================================================

    msedgewebview2(10376)[C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115 (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\144.0.3719.115\msedgewebview2.exe" --type=gpu-process --noerrdialogs --user-data-dir="C:\Users\r.andrews\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView" --webview-exe-name=msteams.exe --webview-exe-version=25227.501.3887.7600 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=2 --gpu-preferences=SAAAAAAAAADgAAAEAAAAAAAAAAAAAGAAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --always-read-main-dll --metrics-shmem-handle=1620,i,16872585971317944761,4301557092349362568,262144 --field-trial-handle=1812,i,73120744137406923,10506569274468041281,262144 --enable-features=msAbydos,msAbydosGestureSupport,msAbydosHandwritingAttr,msSingleSignOnOSForPrimaryAccountIsShared,msWebView2EnableDraggableRegions,msWebView2SetUserAgentOverrideOnIframes,msWebView2TerminateServiceWorkerWhenIdleIgnoringCdpSessions --disable-features=BreakoutBoxPreferCaptureTimestampInVideoFrames,msWebOOUI --variations-seed-version --trace-process-track-uuid=3190708988185955192 --mojo-platform-channel-handle=1800 /prefetch:2
   =================================================================================================

    svchost(2616)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s DevQueryBroker
   =================================================================================================

    mimikatz(10804)[C:\Users\Administrator\Desktop\mimikatz.exe] -- POwn: SYSTEM
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\Administrator\Desktop (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Users\Administrator\Desktop\mimikatz.exe"
   =================================================================================================

    svchost(7784)[C:\Windows\system32\svchost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
   =================================================================================================

    dwm(3904)[C:\Windows\system32\dwm.exe] -- POwn: DWM-2
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: "dwm.exe"
   =================================================================================================

    svchost(2608)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc
   =================================================================================================

    svchost(452)[C:\Windows\system32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k RPCSS -p
   =================================================================================================

    WmiApSrv(1872)[C:\Windows\system32\wbem\WmiApSrv.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32\wbem (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\wbem\WmiApSrv.exe
   =================================================================================================

    RuntimeBroker(7968)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    xampp-control(8204)[C:\xampp\xampp-control.exe] -- POwn: r.andrews
    Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking folder: C:\xampp (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Command Line: "C:\xampp\xampp-control.exe"
   =================================================================================================

    svchost(1504)[C:\Windows\system32\svchost.exe] -- POwn: NETWORK SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k NetworkService -p
   =================================================================================================

    svchost(9060)[C:\Windows\system32\svchost.exe] -- POwn: r.andrews
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
   =================================================================================================

    svchost(5180)[C:\Windows\System32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -s RmSvc
   =================================================================================================

    msedge(8196)[C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe] -- POwn: r.andrews
    Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Program Files (x86)\Microsoft\Edge\Application (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Command Line: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=edge_search_indexer.mojom.SearchIndexerInterfaceBroker --lang=en-US --service-sandbox-type=search_indexer --message-loop-type-ui --always-read-main-dll --metrics-shmem-handle=4176,i,11459255650276672419,2774135882485310256,524288 --field-trial-handle=1992,i,16666200583148690226,6383716170926131157,262144 --variations-seed-version --trace-process-track-uuid=3190708996619331833 --mojo-platform-channel-handle=4280 /prefetch:14
   =================================================================================================

    svchost(2500)[C:\Windows\system32\svchost.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k LocalService -p -s FontCache
   =================================================================================================

    svchost(3020)[C:\Windows\system32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\system32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\system32\svchost.exe -k netsvcs -p -s UserManager
   =================================================================================================

    svchost(5604)[C:\Windows\System32\svchost.exe] -- POwn: SYSTEM
    Possible DLL Hijacking folder: C:\Windows\System32 (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Command Line: C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s DsSvc
   =================================================================================================


����������͹ Vulnerable Leaked Handlers
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#leaked-handlers
� Getting Leaked Handlers, it might take some time...
  [X] Exception: Requested registry access is not allowed.


�����������������������������������͹ Services Information �������������������������������������

����������͹ Interesting Services -non Microsoft-
� Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
    Apache2.4(Apache Software Foundation - Apache2.4)["C:\xampp\apache\bin\httpd.exe" -k runservice] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: GenericExecute (Start/Stop), AllAccess
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\xampp\apache\bin (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])
    Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
   =================================================================================================

    mysql(mysql)[C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql] - Auto - Running - No quotes and Space detected
    YOU CAN MODIFY THIS SERVICE: GenericExecute (Start/Stop), AllAccess
    File Permissions: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Possible DLL Hijacking in binary folder: C:\xampp\mysql\bin (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
   =================================================================================================

    ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    YOU CAN MODIFY THIS SERVICE: Start, GenericExecute (Start/Stop), AllAccess
    Possible DLL Hijacking in binary folder: C:\Windows\System32\OpenSSH (SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    Agent to hold private keys used for public key authentication.
   =================================================================================================

    VGAuthService(Broadcom Inc. - VMware Alias Manager and Ticket Service)["C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: GenericExecute (Start/Stop), AllAccess
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\VMware\VMware Tools\VMware VGAuth (Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess])
    Alias Manager and Ticket Service
   =================================================================================================

    VM3DService(Broadcom Inc. - VMware SVGA Helper Service)["C:\Program Files\VMware\VMware Tools\vm3dservice.exe"] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: GenericExecute (Start/Stop), AllAccess
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\VMware\VMware Tools (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Helps VMware SVGA driver by collecting and conveying user mode information.
   =================================================================================================

    VMTools(Broadcom Inc. - VMware Tools)["C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: GenericExecute (Start/Stop), AllAccess
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files\VMware\VMware Tools (SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    Provides support for synchronizing objects between the host and guest operating systems.
   =================================================================================================


����������͹ Modifiable Services
� Check if you can modify any service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
    LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    AJRouter: GenericExecute (Start/Stop), AllAccess
    ALG: GenericExecute (Start/Stop), AllAccess
    Apache2.4: GenericExecute (Start/Stop), AllAccess
    AppIDSvc: GenericExecute (Start/Stop), AllAccess
    Appinfo: GenericExecute (Start/Stop), AllAccess
    AppMgmt: AllAccess
    AppReadiness: GenericExecute (Start/Stop), AllAccess
    AppVClient: Start, AllAccess
    AppXSvc: GenericExecute (Start/Stop)
    AssignedAccessManagerSvc: GenericExecute (Start/Stop), AllAccess
    AudioEndpointBuilder: GenericExecute (Start/Stop), AllAccess
    Audiosrv: GenericExecute (Start/Stop), AllAccess
    autotimesvc: GenericExecute (Start/Stop), AllAccess
    AxInstSV: GenericExecute (Start/Stop), AllAccess
    BDESVC: Start, ChangeConfig
    BFE: ChangeConfig, WriteDac
    BITS: AllAccess
    BrokerInfrastructure: ChangeConfig, WriteDac
    BTAGService: GenericExecute (Start/Stop), AllAccess
    BthAvctpSvc: GenericExecute (Start/Stop), AllAccess
    bthserv: GenericExecute (Start/Stop), AllAccess
    camsvc: GenericExecute (Start/Stop), AllAccess
    CDPSvc: GenericExecute (Start/Stop), AllAccess
    CertPropSvc: AllAccess, ChangeConfig
    ClipSVC: Start, ChangeConfig, WriteDac
    cloudidsvc: Start, GenericExecute (Start/Stop), AllAccess
    COMSysApp: GenericExecute (Start/Stop), AllAccess
    CoreMessagingRegistrar: GenericExecute (Start/Stop)
    CryptSvc: GenericExecute (Start/Stop), AllAccess
    CscService: GenericExecute (Start/Stop), AllAccess
    DcomLaunch: ChangeConfig, WriteDac
    dcsvc: GenericExecute (Start/Stop), AllAccess
    defragsvc: GenericExecute (Start/Stop), AllAccess
    DeviceAssociationService: GenericExecute (Start/Stop), AllAccess
    DeviceInstall: GenericExecute (Start/Stop), AllAccess
    DevQueryBroker: GenericExecute (Start/Stop), AllAccess
    Dhcp: GenericExecute (Start/Stop), AllAccess
    diagnosticshub.standardcollector.service: GenericExecute (Start/Stop), AllAccess
    diagsvc: GenericExecute (Start/Stop), AllAccess
    DiagTrack: GenericExecute (Start/Stop), AllAccess
    DialogBlockingService: GenericExecute (Start/Stop), AllAccess
    DispBrokerDesktopSvc: GenericExecute (Start/Stop), AllAccess
    DisplayEnhancementService: Start, GenericExecute (Start/Stop), AllAccess
    DmEnrollmentSvc: GenericExecute (Start/Stop), AllAccess
    dmwappushservice: Start, AllAccess
    DoSvc: Start, AllAccess
    dot3svc: GenericExecute (Start/Stop), AllAccess
    DPS: AllAccess, ChangeConfig
    DsmSvc: GenericExecute (Start/Stop), AllAccess
    DsSvc: Start, AllAccess
    DusmSvc: GenericExecute (Start/Stop), AllAccess
    EapHost: GenericExecute (Start/Stop), AllAccess
    edgeupdate: GenericExecute (Start/Stop), AllAccess
    edgeupdatem: GenericExecute (Start/Stop), AllAccess
    EFS: Start, AllAccess, ChangeConfig
    embeddedmode: AllAccess, GenericExecute (Start/Stop)
    EntAppSvc: GenericExecute (Start/Stop)
    EventLog: GenericExecute (Start/Stop), AllAccess
    EventSystem: GenericExecute (Start/Stop), AllAccess
    Fax: Start, AllAccess
    fdPHost: GenericExecute (Start/Stop), AllAccess
    FDResPub: GenericExecute (Start/Stop), AllAccess
    fhsvc: Start, GenericExecute (Start/Stop), AllAccess
    FontCache: GenericExecute (Start/Stop), AllAccess
    FrameServer: GenericExecute (Start/Stop), AllAccess
    FrameServerMonitor: GenericExecute (Start/Stop), AllAccess
    gpsvc: AllAccess
    GraphicsPerfSvc: GenericExecute (Start/Stop), AllAccess
    hidserv: GenericExecute (Start/Stop), AllAccess
    HvHost: GenericExecute (Start/Stop), AllAccess
    icssvc: Start, GenericExecute (Start/Stop), AllAccess
    IKEEXT: GenericExecute (Start/Stop), AllAccess
    InstallService: GenericExecute (Start/Stop), AllAccess
    iphlpsvc: GenericExecute (Start/Stop), AllAccess
    IpxlatCfgSvc: GenericExecute (Start/Stop), AllAccess
    KeyIso: GenericExecute (Start/Stop), AllAccess
    KtmRm: GenericExecute (Start/Stop), AllAccess
    LanmanServer: GenericExecute (Start/Stop), AllAccess
    LanmanWorkstation: GenericExecute (Start/Stop), AllAccess
    lfsvc: AllAccess
    LicenseManager: GenericExecute (Start/Stop), AllAccess
    lltdsvc: GenericExecute (Start/Stop), AllAccess
    lmhosts: GenericExecute (Start/Stop), AllAccess
    LSM: ChangeConfig
    LxpSvc: GenericExecute (Start/Stop), AllAccess
    MapsBroker: Start, AllAccess
    McpManagementService: GenericExecute (Start/Stop), AllAccess
    MicrosoftEdgeElevationService: GenericExecute (Start/Stop), AllAccess
    MixedRealityOpenXRSvc: GenericExecute (Start/Stop), AllAccess
    mpssvc: ChangeConfig, WriteDac
    MSDTC: ChangeConfig
    MSiSCSI: GenericExecute (Start/Stop), AllAccess
    msiserver: GenericExecute (Start/Stop)
    MsKeyboardFilter: GenericExecute (Start/Stop), AllAccess
    mysql: GenericExecute (Start/Stop), AllAccess
    NaturalAuthentication: GenericExecute (Start/Stop), AllAccess
    NcaSvc: GenericExecute (Start/Stop), AllAccess
    NcbService: GenericExecute (Start/Stop), AllAccess
    NcdAutoSetup: GenericExecute (Start/Stop), AllAccess
    Netlogon: GenericExecute (Start/Stop), AllAccess
    Netman: GenericExecute (Start/Stop), AllAccess
    netprofm: GenericExecute (Start/Stop), AllAccess
    NetSetupSvc: AllAccess
    NetTcpPortSharing: GenericExecute (Start/Stop), AllAccess
    NgcCtnrSvc: ChangeConfig, WriteDac
    NgcSvc: ChangeConfig, WriteDac
    NICQueueSvc: GenericExecute (Start/Stop), AllAccess
    NlaSvc: GenericExecute (Start/Stop), AllAccess
    nsi: GenericExecute (Start/Stop), AllAccess
    p2pimsvc: AllAccess
    p2psvc: AllAccess
    PcaSvc: GenericExecute (Start/Stop), AllAccess
    PeerDistSvc: AllAccess
    perceptionsimulation: GenericExecute (Start/Stop), AllAccess
    PerfHost: GenericExecute (Start/Stop), AllAccess
    PhoneSvc: Start, AllAccess
    pla: Start, GenericExecute (Start/Stop), AllAccess
    PlugPlay: GenericExecute (Start/Stop), AllAccess
    PNRPAutoReg: AllAccess
    PNRPsvc: AllAccess
    PolicyAgent: GenericExecute (Start/Stop), AllAccess
    Power: GenericExecute (Start/Stop), AllAccess
    PrintNotify: GenericExecute (Start/Stop), AllAccess
    ProfSvc: GenericExecute (Start/Stop), AllAccess
    PushToInstall: GenericExecute (Start/Stop), AllAccess
    QWAVE: AllAccess
    RasAuto: GenericExecute (Start/Stop), AllAccess
    RasMan: Start, AllAccess
    RemoteAccess: GenericExecute (Start/Stop), AllAccess
    RemoteRegistry: GenericExecute (Start/Stop), AllAccess
    RetailDemo: GenericExecute (Start/Stop), AllAccess
    RmSvc: ChangeConfig
    RpcEptMapper: ChangeConfig, WriteDac
    RpcLocator: GenericExecute (Start/Stop), AllAccess
    RpcSs: ChangeConfig, WriteDac
    SamSs: AllAccess
    SCardSvr: AllAccess, ChangeConfig
    ScDeviceEnum: AllAccess, ChangeConfig
    Schedule: AllAccess, WriteDac
    SCPolicySvc: AllAccess, ChangeConfig
    SDRSVC: GenericExecute (Start/Stop), AllAccess
    seclogon: Start, GenericExecute (Start/Stop), AllAccess
    SEMgrSvc: AllAccess
    SENS: GenericExecute (Start/Stop), AllAccess
    Sense: GenericExecute (Start/Stop), ChangeConfig
    SensorDataService: GenericExecute (Start/Stop), AllAccess
    SensorService: Start, GenericExecute (Start/Stop), AllAccess
    SensrSvc: Start, GenericExecute (Start/Stop), AllAccess
    SessionEnv: GenericExecute (Start/Stop), AllAccess
    SgrmBroker: GenericExecute (Start/Stop), AllAccess
    SharedAccess: GenericExecute (Start/Stop), AllAccess
    SharedRealitySvc: GenericExecute (Start/Stop), AllAccess
    ShellHWDetection: GenericExecute (Start/Stop), AllAccess
    shpamsvc: GenericExecute (Start/Stop), AllAccess
    smphost: Start, GenericExecute (Start/Stop), AllAccess
    SmsRouter: ChangeConfig
    SNMPTrap: GenericExecute (Start/Stop), AllAccess
    spectrum: GenericExecute (Start/Stop), AllAccess
    Spooler: GenericExecute (Start/Stop), AllAccess
    sppsvc: Start, ChangeConfig, WriteDac
    SSDPSRV: AllAccess
    ssh-agent: Start, GenericExecute (Start/Stop), AllAccess
    SstpSvc: Start, GenericExecute (Start/Stop), AllAccess
    StateRepository: GenericExecute (Start/Stop)
    StiSvc: GenericExecute (Start/Stop), AllAccess
    StorSvc: GenericExecute (Start/Stop), AllAccess
    svsvc: GenericExecute (Start/Stop), AllAccess
    swprv: GenericExecute (Start/Stop), AllAccess
    SysMain: GenericExecute (Start/Stop), AllAccess
    SystemEventsBroker: ChangeConfig, WriteDac
    TabletInputService: Start, GenericExecute (Start/Stop), AllAccess
    TapiSrv: GenericExecute (Start/Stop), AllAccess
    TermService: GenericExecute (Start/Stop), AllAccess
    Themes: GenericExecute (Start/Stop), AllAccess
    TieringEngineService: GenericExecute (Start/Stop), AllAccess
    TimeBrokerSvc: ChangeConfig, WriteDac
    TokenBroker: GenericExecute (Start/Stop), AllAccess
    TrkWks: GenericExecute (Start/Stop), AllAccess
    TroubleshootingSvc: GenericExecute (Start/Stop), AllAccess
    TrustedInstaller: AllAccess, ChangeConfig
    tzautoupdate: GenericExecute (Start/Stop), AllAccess
    UevAgentService: Start, AllAccess
    uhssvc: GenericExecute (Start/Stop), AllAccess
    UmRdpService: GenericExecute (Start/Stop), AllAccess
    upnphost: AllAccess
    UserManager: GenericExecute (Start/Stop), AllAccess
    UsoSvc: Start, AllAccess
    VacSvc: GenericExecute (Start/Stop), AllAccess
    VaultSvc: GenericExecute (Start/Stop), AllAccess
    vds: GenericExecute (Start/Stop), AllAccess
    VGAuthService: GenericExecute (Start/Stop), AllAccess
    VM3DService: GenericExecute (Start/Stop), AllAccess
    vmicguestinterface: GenericExecute (Start/Stop), AllAccess
    vmicheartbeat: GenericExecute (Start/Stop), AllAccess
    vmickvpexchange: GenericExecute (Start/Stop), AllAccess
    vmicrdv: GenericExecute (Start/Stop), AllAccess
    vmicshutdown: GenericExecute (Start/Stop), AllAccess
    vmictimesync: GenericExecute (Start/Stop), AllAccess
    vmicvmsession: GenericExecute (Start/Stop), AllAccess
    vmicvss: GenericExecute (Start/Stop), AllAccess
    VMTools: GenericExecute (Start/Stop), AllAccess
    vmvss: GenericExecute (Start/Stop), AllAccess
    VSS: GenericExecute (Start/Stop), AllAccess
    W32Time: GenericExecute (Start/Stop), AllAccess
    WaaSMedicSvc: Start, AllAccess
    WalletService: GenericExecute (Start/Stop), AllAccess
    WarpJITSvc: GenericExecute (Start/Stop), AllAccess
    wbengine: GenericExecute (Start/Stop), AllAccess
    WbioSrvc: GenericExecute (Start/Stop), AllAccess
    Wcmsvc: GenericExecute (Start/Stop), AllAccess
    wcncsvc: AllAccess
    WdiServiceHost: AllAccess, ChangeConfig
    WdiSystemHost: AllAccess, ChangeConfig
    WebClient: GenericExecute (Start/Stop), AllAccess
    Wecsvc: GenericExecute (Start/Stop), AllAccess
    WEPHOSTSVC: GenericExecute (Start/Stop), AllAccess
    wercplsupport: GenericExecute (Start/Stop), AllAccess
    WerSvc: GenericExecute (Start/Stop), AllAccess
    WFDSConMgrSvc: GenericExecute (Start/Stop), AllAccess
    WiaRpc: GenericExecute (Start/Stop), AllAccess
    Winmgmt: GenericExecute (Start/Stop), AllAccess
    WinRM: GenericExecute (Start/Stop), AllAccess
    wisvc: GenericExecute (Start/Stop), AllAccess
    WlanSvc: GenericExecute (Start/Stop), AllAccess
    wlidsvc: GenericExecute (Start/Stop), AllAccess
    wlpasvc: GenericExecute (Start/Stop), AllAccess
    WManSvc: GenericExecute (Start/Stop), AllAccess
    wmiApSrv: GenericExecute (Start/Stop), AllAccess
    WMPNetworkSvc: GenericExecute (Start/Stop), AllAccess
    workfolderssvc: GenericExecute (Start/Stop), AllAccess
    WpcMonSvc: GenericExecute (Start/Stop), AllAccess
    WPDBusEnum: GenericExecute (Start/Stop), AllAccess
    WpnService: GenericExecute (Start/Stop), AllAccess
    WSearch: GenericExecute (Start/Stop), AllAccess
    wuauserv: Start, AllAccess
    WwanSvc: GenericExecute (Start/Stop), AllAccess
    XblAuthManager: GenericExecute (Start/Stop), AllAccess
    XblGameSave: GenericExecute (Start/Stop), AllAccess
    XboxGipSvc: GenericExecute (Start/Stop), AllAccess
    XboxNetApiSvc: GenericExecute (Start/Stop), AllAccess
    AarSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    BcastDVRUserService_7ec239: GenericExecute (Start/Stop), AllAccess
    BluetoothUserService_7ec239: GenericExecute (Start/Stop), AllAccess
    CaptureService_7ec239: GenericExecute (Start/Stop), AllAccess
    cbdhsvc_7ec239: GenericExecute (Start/Stop), AllAccess
    CDPUserSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    ConsentUxUserSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    CredentialEnrollmentManagerUserSvc_7ec239: GenericExecute (Start/Stop)
    DeviceAssociationBrokerSvc_7ec239: GenericExecute (Start/Stop)
    DevicePickerUserSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    DevicesFlowUserSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    MessagingService_7ec239: GenericExecute (Start/Stop), AllAccess
    NPSMSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    OneSyncSvc_7ec239: Start, AllAccess
    P9RdrService_7ec239: GenericExecute (Start/Stop), AllAccess
    PenService_7ec239: GenericExecute (Start/Stop), AllAccess
    PimIndexMaintenanceSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    PrintWorkflowUserSvc_7ec239: GenericExecute (Start/Stop)
    UdkUserSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    UnistoreSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    UserDataSvc_7ec239: GenericExecute (Start/Stop), AllAccess
    WpnUserService_7ec239: GenericExecute (Start/Stop), AllAccess

����������͹ Looking if you can modify any service registry
� Check if you can modify the registry of a service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services-registry-modify-permissions
    HKLM\system\currentcontrolset\services\.NET CLR Data (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\.NET CLR Networking (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\.NET CLR Networking 4.0.0.0 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\.NET Data Provider for Oracle (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\.NET Data Provider for SqlServer (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\.NET Memory Cache 4.0 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\.NETFramework (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\1394ohci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\3ware (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AarSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AarSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ACPI (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AcpiDev (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\acpiex (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\acpipagr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AcpiPmi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\acpitime (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Acx01000 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ADOVMPPackage (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ADP80XX (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\adsi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AFD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\afunix (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ahcache (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AJRouter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ALG (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\amdgpio2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\amdi2c (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AmdK8 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AmdPPM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\amdsata (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\amdsbs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\amdxata (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Apache2.4 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppID (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppIDSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Appinfo (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppleSSD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\applockerfltr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppMgmt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppReadiness (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppVClient (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppvStrm (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppvVemgr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppvVfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AppXSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\arcsas (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AssignedAccessManagerSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AsyncMac (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\atapi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AudioEndpointBuilder (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Audiosrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\autotimesvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\AxInstSV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\b06bdrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\bam (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BasicDisplay (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BasicRender (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BattC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BcastDVRUserService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BcastDVRUserService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\bcmfn2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BDESVC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Beep (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BFE (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\bindflt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BITS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BluetoothUserService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BluetoothUserService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\bowser (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BrokerInfrastructure (SYSTEM [Allow: FullControl], Administrators [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BTAGService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BthA2dp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BthAvctpSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BthEnum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BthHFEnum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BthLEEnum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BthMini (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BTHMODEM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BTHPORT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\bthserv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\BTHUSB (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\bttflt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\buttonconverter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CAD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\camsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CaptureService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CaptureService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cbdhsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cbdhsvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cdfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CDPSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CDPUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CDPUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cdrom (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CertPropSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cht4iscsi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cht4vbd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CimFS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\circlass (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CldFlt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CLFS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ClipSVC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cloudidsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\clr_optimization_v4.0.30319_32 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\clr_optimization_v4.0.30319_64 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CmBatt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CNG (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\cnghwassist (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CompositeBus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\COMSysApp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\condrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ConsentUxUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ConsentUxUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CoreMessagingRegistrar (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CoreUI (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CredentialEnrollmentManagerUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CredentialEnrollmentManagerUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\crypt32 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CryptSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CSC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\CscService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\dam (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DCLocator (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DcomLaunch (SYSTEM [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\dcsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\defragsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DeviceAssociationBrokerSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DeviceAssociationBrokerSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DeviceAssociationService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DeviceInstall (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DevicePickerUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DevicePickerUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DevicesFlowUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DevicesFlowUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DevQueryBroker (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Dfsc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Dhcp (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\diagnosticshub.standardcollector.service (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\diagsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DiagTrack (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DialogBlockingService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\disk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DispBrokerDesktopSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DisplayEnhancementService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DmEnrollmentSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\dmvsc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\dmwappushservice (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Dnscache (SYSTEM [Allow: FullControl], Administrators [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DoSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\dot3svc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DPS (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\drmkaud (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DsmSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DsSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DusmSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\DXGKrnl (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\e1i68x64 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\EapHost (Administrators [Allow: WriteKey FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ebdrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ebdrv0 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\edgeupdate (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\edgeupdatem (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\EFS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\EhStorClass (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\EhStorTcgDrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\embeddedmode (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\EntAppSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ErrDev (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ESENT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\EventLog (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\EventSystem (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ExecutionContext (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\exfat (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\fastfat (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Fax (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\fdc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\fdPHost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FDResPub (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\fhsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FileCrypt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FileInfo (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Filetrace (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\flpydisk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FltMgr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FontCache (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FrameServer (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FrameServerMonitor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\FsDepends (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Fs_Rec (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\fvevol (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\gencounter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\genericusbfn (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\GPIOClx0101 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\gpsvc (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\GpuEnergyDrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\GraphicsPerfSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HdAudAddService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HDAudBus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HidBatt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HidBth (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hidi2c (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hidinterrupt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HidIr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hidserv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hidspi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HidSpiCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HidUsb (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HpSAMD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Hsp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HTTP (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hvcrash (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HvHost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hvservice (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HwNClx0101 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hwpolicy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\hyperkbd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\HyperVideo (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\i8042prt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iagpio (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iai2c (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_GPIO2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_GPIO2_BXT_P (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_GPIO2_CNL (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_GPIO2_GLK (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_I2C (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_I2C_BXT_P (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_I2C_CNL (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSS2i_I2C_GLK (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSSi_GPIO (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaLPSSi_I2C (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaStorAV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaStorAVC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iaStorV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ibbus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\icssvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IKEEXT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IndirectKmd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\inetaccs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\InstallService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\intelide (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\intelpep (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\intelpmax (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IntelPMT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\intelppm (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iorate (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IpFilterDriver (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iphlpsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IPMIDRV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IPNAT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IPT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\IpxlatCfgSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\isapnp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\iScsiPrt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ItSas35i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\kbdclass (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\kbdhid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\kbldfltr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\kdnic (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\KeyIso (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\KSecDD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\KSecPkg (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\KslD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ksthunk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\KtmRm (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LanmanServer (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LanmanWorkstation (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ldap (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\lfsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LicenseManager (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\lltdio (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\lltdsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\lmhosts (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LSI_SAS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LSI_SAS2i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LSI_SAS3i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LSM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\luafv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\LxpSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MapsBroker (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mausbhost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mausbip (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MbbCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\McpManagementService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MDCoreSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\megasas2i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\megasas35i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\megasr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MessagingService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MessagingService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MicrosoftEdgeElevationService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Microsoft_Bluetooth_AvrcpTransport (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MixedRealityOpenXRSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mlx4_bus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MMCSS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Modem (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\monitor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mouclass (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mouhid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mountmgr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mpi3drvi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mpsdrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mpssvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MRxDAV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mrxsmb (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mrxsmb20 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsBridge (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSDTC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSDTC Bridge 4.0.0.0 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Msfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\msgpiowin32 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mshidkmdf (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mshidumdf (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\msisadrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSiSCSI (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\msiserver (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsKeyboardFilter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSKSSRV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsLldp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSPCLOCK (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSPQM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsQuic (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsRPC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsSecCore (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsSecFlt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MsSecWfp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mssmbios (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MSTEE (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\MTConfig (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Mup (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mvumis (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\mysql (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\napagent (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NativeWifiP (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NaturalAuthentication (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NcaSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NcbService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NcdAutoSetup (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ndfltr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NDIS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NdisCap (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NdisImPlatform (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NdisTapi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Ndisuio (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NdisVirtualBus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NdisWan (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ndiswanlegacy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NDKPerf (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NDKPing (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ndproxy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Ndu (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NetAdapterCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NetBIOS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NetbiosSmb (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NetBT (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\Netlogon (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Netman (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\netprofm (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NetSetupSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NetTcpPortSharing (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\netvsc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\netvscvfpp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NgcCtnrSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NgcSvc (SYSTEM [Allow: TakeOwnership FullControl], Administrators [Allow: TakeOwnership FullControl])
    HKLM\system\currentcontrolset\services\NICQueueSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NlaSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Npfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NPSMSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NPSMSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\npsvctrig (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\nsi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\nsiproxy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\NTDS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Ntfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Null (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\nvdimm (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\nvmedisk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\nvraid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\nvstor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\OneSyncSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\OneSyncSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\p2pimsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\p2psvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\P9NP (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\P9Rdr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\P9RdrService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\P9RdrService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Parport (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\partmgr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PcaSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pciide (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pcmcia (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pcw (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pdc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PEAUTH (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PeerDistSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PenService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PenService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\perceptionsimulation (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\percsas2i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\percsas3i (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PerfDisk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PerfHost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PerfNet (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PerfOS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PerfProc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PhoneSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PimIndexMaintenanceSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PimIndexMaintenanceSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PktMon (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pla (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PlugPlay (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pmem (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PNPMEM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PNRPAutoReg (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PNRPsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PolicyAgent (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\portcfg (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PortProxy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Power (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PptpMiniport (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PrintNotify (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PrintWorkflowUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PrintWorkflowUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PRM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Processor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ProfSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Psched (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\PushToInstall (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\pvscsi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\QWAVE (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\QWAVEdrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Ramdisk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RasAcd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RasAgileVpn (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RasAuto (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\Rasl2tp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RasMan (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\RasPppoe (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RasSstp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\rdbss (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RDMANDK (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\rdpbus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RDPDR (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RDPNP (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RDPUDD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RdpVideoMiniport (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\rdyboost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ReFS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ReFSv1 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RemoteAccess (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\RemoteRegistry (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RetailDemo (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RFCOMM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\rhproxy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RmSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RpcEptMapper (SYSTEM [Allow: TakeOwnership FullControl], Administrators [Allow: TakeOwnership FullControl])
    HKLM\system\currentcontrolset\services\RpcLocator (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\RpcSs (SYSTEM [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\rspndr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\s3cap (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SamSs (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\sbp2port (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SCardSvr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ScDeviceEnum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\scfilter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Schedule (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\scmbus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SCPolicySvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\sdbus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SDFRd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SDRSVC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\sdstor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\seclogon (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SecurityHealthService (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\SEMgrSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SENS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Sense (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SensorDataService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SensorService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SensrSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SerCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SerCx2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Serenum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Serial (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\sermouse (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SessionEnv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\sfloppy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SgrmAgent (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SgrmBroker (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SharedAccess (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SharedRealitySvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ShellHWDetection (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\shpamsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SiSRaid2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SiSRaid4 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SmartSAMD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\smbdirect (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\smphost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SmsRouter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SMSvcHost 4.0.0.0 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SNMPTrap (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\spaceparser (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\spaceport (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SpatialGraphFilter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SpbCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\spectrum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Spooler (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\sppsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\srv2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\srvnet (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SSDPSRV (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ssh-agent (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SstpSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\StateRepository (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\stexstor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\StiSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\storahci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\storflt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\stornvme (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\storqosflt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\StorSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\storufs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\storvsc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\svsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\swenum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\swprv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SysMain (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\SystemEventsBroker (SYSTEM [Allow: FullControl], Administrators [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TabletInputService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TapiSrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Tcpip (SYSTEM [Allow: FullControl], Administrators [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Tcpip6 (SYSTEM [Allow: FullControl], Administrators [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TCPIP6TUNNEL (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\tcpipreg (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TCPIPTUNNEL (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\tdx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\terminpt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TermService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Themes (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TieringEngineService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TimeBrokerSvc (SYSTEM [Allow: FullControl], Administrators [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TokenBroker (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TPM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TrkWks (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\TroubleshootingSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TrustedInstaller (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\TSDDD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TsUsbFlt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\TsUsbGD (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\tsusbhub (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\tunnel (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\tzautoupdate (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UASPStor (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UcmCx0101 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UcmTcpciCx0101 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UcmUcsiAcpiClient (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UcmUcsiCx0101 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Ucx01000 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UdeCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\udfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UdkUserSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UdkUserSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UEFI (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UevAgentDriver (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UevAgentService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Ufx01000 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UfxChipidea (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ufxsynopsys (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UGatherer (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UGTHRSVC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\uhssvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\umbus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UmPass (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UmRdpService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UnistoreSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UnistoreSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\upnphost (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UrsChipidea (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UrsCx01000 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UrsSynopsys (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Usb4DeviceRouter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Usb4HostRouter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbaudio (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbaudio2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbccgp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbcir (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbehci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbhub (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\USBHUB3 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbohci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbprint (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbser (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\USBSTOR (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\usbuhci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\USBXHCI (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UserDataSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UserDataSvc_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UserManager (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\UsoSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VacSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VaultSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vdrvroot (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vds (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VerifierExt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VGAuthService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vhdmp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vhf (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Vid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VirtualRender (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vm3dmp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vm3dmp-debug (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vm3dmp-stats (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vm3dmp_loader (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VM3DService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmbus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VMBusHID (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmgid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmhgfs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmicguestinterface (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmicheartbeat (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmickvpexchange (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmicrdv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmicshutdown (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmictimesync (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmicvmsession (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmicvss (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VMMemCtl (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmmouse (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmrawdsk (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VMTools (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmusbmouse (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmvss (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmwefifw (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vmxnet3ndis6 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vnetWFP (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\volmgr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\volmgrx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\volsnap (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\volume (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vpci (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vsepflt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vsmraid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vsock (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VSS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\VSTXRAID (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vwifibus (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\vwififlt (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\W32Time (SYSTEM [Allow: GenericAll FullControl], Administrators [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\WaaSMedicSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WacomPen (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WalletService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wanarp (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wanarpv6 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WarpJITSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wbengine (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WbioSrvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wcifs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Wcmsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wcncsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WdBoot (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Wdf01000 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WdFilter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WdiServiceHost (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\WdiSystemHost (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\wdiwifi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WdmCompanionFilter (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WdNisDrv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WdNisSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WebClient (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Wecsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WEPHOSTSVC (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wercplsupport (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WerSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WFDSConMgrSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WFPLWFS (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WiaRpc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WifiCx (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WIMMount (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WinDefend (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Windows Workflow Foundation 4.0.0.0 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WindowsTrustedRT (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WindowsTrustedRTProxy (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WinHttpAutoProxySvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WinMad (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Winmgmt (SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\WinNat (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WinRM (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Winsock (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WinSock2 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WINUSB (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WinVerbs (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wisvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WlanSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wlidsvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wlpasvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WManSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WmiAcpi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WmiApRpl (SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\wmiApSrv (SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: GenericAll FullControl])
    HKLM\system\currentcontrolset\services\WMPNetworkSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\Wof (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\workerdd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\workfolderssvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WpcMonSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WPDBusEnum (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WpdUpFltr (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WpnService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WpnUserService (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WpnUserService_7ec239 (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\ws2ifsl (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wscsvc (SYSTEM [Allow: FullControl GenericAll])
    HKLM\system\currentcontrolset\services\WSearch (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WSearchIdxPi (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\wuauserv (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WudfPf (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WUDFRd (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\WwanSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\XblAuthManager (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\XblGameSave (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\xboxgip (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\XboxGipSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\XboxNetApiSvc (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\xinputhid (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\xmlprov (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\{BF7D0378-CFF0-4E33-9336-AD542BDD5A28} (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])
    HKLM\system\currentcontrolset\services\{FBBCECE6-F3D0-41A7-B314-6E124CD6E55F} (Administrators [Allow: FullControl], SYSTEM [Allow: FullControl])

����������͹ Checking write permissions in PATH folders (DLL Hijacking)
� Check for DLL Hijacking in PATH folders https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking
    (DLL Hijacking) C:\Windows\system32: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    (DLL Hijacking) C:\Windows: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    (DLL Hijacking) C:\Windows\System32\Wbem: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    (DLL Hijacking) C:\Windows\System32\WindowsPowerShell\v1.0\: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    (DLL Hijacking) C:\Windows\System32\OpenSSH\: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]


�����������������������������������͹ Applications Information �������������������������������������

����������͹ Current Active Window Application
  [X] Exception: Object reference not set to an instance of an object.

����������͹ Installed Applications --Via Program Files/Uninstall registry--
� Check if you can modify installed software https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#applications
    C:\Program Files\Common Files(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\desktop.ini(SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    C:\Program Files\Internet Explorer(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Microsoft Update Health Tools(SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    C:\Program Files\ModifiableWindowsApps(SYSTEM [Allow: AllAccess])
    C:\Program Files\OffSec NIC(SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    C:\Program Files\RUXIM(SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    C:\Program Files\Uninstall Information(SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    C:\Program Files\VMware(SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess])
    C:\Program Files\Windows Defender(SYSTEM [Allow: AllAccess], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Windows Defender Advanced Threat Protection(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Windows Mail(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Windows Media Player(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Windows NT(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Windows Photo Viewer(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\Windows Sidebar(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\Program Files\WindowsApps(SYSTEM [Allow: AllAccess])
    C:\Program Files\WindowsPowerShell(SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles])
    C:\xampp(Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles])


����������͹ Autorun Applications
� Check if you can modify other users AutoRuns binaries (Note that is normal that you can modify HKCU registry and binaries indicated there) https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html

    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    RegPerms: Administrators [Allow: FullControl GenericAll], SYSTEM [Allow: FullControl GenericAll]
    Key: SecurityHealth
    Folder: C:\Windows\system32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\system32\SecurityHealthSystray.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    RegPerms: Administrators [Allow: FullControl GenericAll], SYSTEM [Allow: FullControl GenericAll]
    Key: VMware User Process
    Folder: C:\Program Files\VMware\VMware Tools
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected) - C:\,C:\Program Files\VMware,C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
    FilePerms: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    RegPerms: Administrators [Allow: FullControl GenericAll], SYSTEM [Allow: FullControl GenericAll]
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess] (Unquoted and Space detected) - C:\ProgramData\Microsoft\Windows,C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: GenericAll FullControl]
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess] (Unquoted and Space detected) - C:\ProgramData\Microsoft\Windows,C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: Userinit
    Folder: C:\Windows\system32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\system32\userinit.exe,
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: Shell
    Folder: None (PATH Injection)
    File: explorer.exe
   =================================================================================================


    RegPath: HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: AlternateShell
    Folder: None (PATH Injection)
    File: cmd.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: aux
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: midi
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: mixer
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: wave
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.l3acm
    Folder: C:\Windows\System32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\System32\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: aux
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: midi
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: mixer
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.cvid
    Folder: None (PATH Injection)
    File: iccvid.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: wave
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    RegPerms: SYSTEM [Allow: FullControl GenericAll], Administrators [Allow: FullControl GenericAll]
    Key: msacm.l3acm
    Folder: C:\Windows\SysWOW64
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\SysWOW64\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Classes\htmlfile\shell\open\command
    RegPerms: Administrators [Allow: FullControl GenericAll], SYSTEM [Allow: FullControl GenericAll]
    Folder: C:\Program Files\Internet Explorer
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Program Files\Internet Explorer\iexplore.exe %1 (Unquoted and Space detected) - C:\,C:\Program Files,C:\Program Files\Internet Explorer\iexplore.exe
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: *kernel32
    Folder: None (PATH Injection)
    File: kernel32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wow64cpu
    Folder: None (PATH Injection)
    File: wow64cpu.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wowarmhw
    Folder: None (PATH Injection)
    File: wowarmhw.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _xtajit
    Folder: None (PATH Injection)
    File: xtajit.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: advapi32
    Folder: None (PATH Injection)
    File: advapi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: clbcatq
    Folder: None (PATH Injection)
    File: clbcatq.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: combase
    Folder: None (PATH Injection)
    File: combase.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: COMDLG32
    Folder: None (PATH Injection)
    File: COMDLG32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: coml2
    Folder: None (PATH Injection)
    File: coml2.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: DifxApi
    Folder: None (PATH Injection)
    File: difxapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdi32
    Folder: None (PATH Injection)
    File: gdi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdiplus
    Folder: None (PATH Injection)
    File: gdiplus.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMAGEHLP
    Folder: None (PATH Injection)
    File: IMAGEHLP.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMM32
    Folder: None (PATH Injection)
    File: IMM32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSCTF
    Folder: None (PATH Injection)
    File: MSCTF.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSVCRT
    Folder: None (PATH Injection)
    File: MSVCRT.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NORMALIZ
    Folder: None (PATH Injection)
    File: NORMALIZ.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NSI
    Folder: None (PATH Injection)
    File: NSI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: ole32
    Folder: None (PATH Injection)
    File: ole32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: OLEAUT32
    Folder: None (PATH Injection)
    File: OLEAUT32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: PSAPI
    Folder: None (PATH Injection)
    File: PSAPI.DLL
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: rpcrt4
    Folder: None (PATH Injection)
    File: rpcrt4.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: sechost
    Folder: None (PATH Injection)
    File: sechost.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: Setupapi
    Folder: None (PATH Injection)
    File: Setupapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHCORE
    Folder: None (PATH Injection)
    File: SHCORE.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHELL32
    Folder: None (PATH Injection)
    File: SHELL32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHLWAPI
    Folder: None (PATH Injection)
    File: SHLWAPI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: user32
    Folder: None (PATH Injection)
    File: user32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WLDAP32
    Folder: None (PATH Injection)
    File: WLDAP32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64
    Folder: None (PATH Injection)
    File: wow64.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64base
    Folder: None (PATH Injection)
    File: wow64base.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64con
    Folder: None (PATH Injection)
    File: wow64con.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64win
    Folder: None (PATH Injection)
    File: wow64win.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WS2_32
    Folder: None (PATH Injection)
    File: WS2_32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: xtajit64
    Folder: None (PATH Injection)
    File: xtajit64.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: \
    FolderPerms: Authenticated Users [Allow: AppendData/CreateDirectories], SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: /UserInstall
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: C:\Windows\system32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: None (PATH Injection)
    File: U
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: C:\Windows\System32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\System32\ie4uinit.exe -UserConfig
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: C:\Windows\System32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\145.0.3800.65\Installer
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Program Files (x86)\Microsoft\Edge\Application\145.0.3800.65\Installer\setup.exe --configure-user-settings --verbose-logging --system-level --msedge --channel=stable (Unquoted and Space detected) - C:\,C:\Program Files
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: C:\Windows\system32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}
    RegPerms: Administrators [Allow: FullControl], SYSTEM [Allow: FullControl]
    Key: StubPath
    Folder: C:\Windows\SysWOW64
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}
    RegPerms: Administrators [Allow: FullControl GenericAll], SYSTEM [Allow: FullControl GenericAll]
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\145.0.3800.65\BHO
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Program Files (x86)\Microsoft\Edge\Application\145.0.3800.65\BHO\ie_to_edge_bho_64.dll (Unquoted and Space detected) - C:\,C:\Program Files
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}
    RegPerms: Administrators [Allow: FullControl GenericAll], SYSTEM [Allow: FullControl GenericAll]
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\145.0.3800.65\BHO
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Program Files (x86)\Microsoft\Edge\Application\145.0.3800.65\BHO\ie_to_edge_bho_64.dll (Unquoted and Space detected) - C:\,C:\Program Files
   =================================================================================================


    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\ProgramData\Microsoft\Windows,C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
    FilePerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles], SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles], SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
   =================================================================================================


    Folder: C:\windows
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\windows\system.ini
    FilePerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
   =================================================================================================


    Folder: C:\windows
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\windows\win.ini
    FilePerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
   =================================================================================================


    Key: From WMIC
    Folder: C:\Windows\SysWOW64
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\SysWOW64\OneDriveSetup.exe /thfirstsetup (Unquoted and Space detected) - C:\Windows\SysWOW64\OneDriveSetup.exe
   =================================================================================================


    Key: From WMIC
    Folder: C:\Windows\SysWOW64
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\SysWOW64\OneDriveSetup.exe /thfirstsetup (Unquoted and Space detected) - C:\Windows\SysWOW64\OneDriveSetup.exe
   =================================================================================================


    Key: From WMIC
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window --win-session-start
    FilePerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
   =================================================================================================


    Key: From WMIC
    Folder: C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background
    FilePerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
   =================================================================================================


    Key: From WMIC
    Folder: C:\Windows\system32
    FolderPerms: SYSTEM [Allow: WriteData/CreateFiles], Administrators [Allow: WriteData/CreateFiles]
    File: C:\Windows\system32\SecurityHealthSystray.exe
   =================================================================================================


    Key: From WMIC
    Folder: C:\Program Files\VMware\VMware Tools
    FolderPerms: SYSTEM [Allow: AllAccess], Administrators [Allow: AllAccess]
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr
    FilePerms: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess]
   =================================================================================================


����������͹ Scheduled Applications --Non Microsoft--
� Check if you can modify other users scheduled binaries https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html

����������͹ Device Drivers --Non Microsoft--
� Check 3rd party drivers for known vulnerabilities/rootkits. https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#drivers
    NVIDIA nForce(TM) RAID Driver - 10.6.0.23 [NVIDIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\nvraid.sys
    QLogic 10 GigE - 7.13.65.105 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\evbd0a.sys
    QLogic 10 GigE - 7.13.171.102 [Marvell Semiconductor Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\evbda.sys
    QLogic Gigabit Ethernet - 7.12.31.105 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxvbda.sys
    VMware vSockets Service - 9.8.22.0 build-24079699 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vsock.sys
    VMware PCI VMCI Bus Device - 9.8.30.0 build-24649440 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmci.sys
    Intel Matrix Storage Manager driver - 8.6.2.1019 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\iaStorV.sys
    VIA RAID driver - 7.0.9600,6352 [VIA Technologies Inc.,Ltd]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vsmraid.sys
    Boot Camp - 6.1.0.0 [Apple Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\AppleSSD.sys
    LSI 3ware RAID Controller - WindowsBlue [LSI]: \\.\GLOBALROOT\SystemRoot\System32\drivers\3ware.sys
    AHCI 1.3 Device Driver - 1.1.3.277 [Advanced Micro Devices]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdsata.sys
    Storage Filter Driver - 1.1.3.277 [Advanced Micro Devices]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdxata.sys
    AMD Technology AHCI Compatible Controller - 3.7.1540.43 [AMD Technologies Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdsbs.sys
    Adaptec RAID Controller - 7.5.0.32048 [PMC-Sierra, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\arcsas.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ItSas35i.sys
    LSI Fusion-MPT SAS Driver (StorPort) - 1.34.03.83 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas2i.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas3i.sys
    MEGASAS2i RAID Controller Driver for Windows - 6.714.22.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\MegaSas2i.sys
    MEGASAS RAID Controller Driver for Windows - 7.717.02.00 [Broadcom Inc]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasas35i.sys
    MegaRAID Software RAID - 15.02.2013.0129 [LSI Corporation, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasr.sys
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Broadcom Limited]: \\.\GLOBALROOT\SystemRoot\System32\drivers\mpi3drvi.sys
    Marvell Flash Controller -  1.0.5.1016  [Marvell Semiconductor, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\mvumis.sys
    NVIDIA nForce(TM) SATA Driver - 10.6.0.23 [NVIDIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\nvstor.sys
    MEGASAS RAID Controller Driver for Windows - 6.805.03.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\percsas2i.sys
    MEGASAS RAID Controller Driver for Windows - 6.604.06.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\percsas3i.sys
    Microsoftr Windowsr Operating System - 2.60.01 [Silicon Integrated Systems Corp.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\SiSRaid2.sys
    Microsoftr Windowsr Operating System - 6.1.6918.0 [Silicon Integrated Systems]: \\.\GLOBALROOT\SystemRoot\System32\drivers\sisraid4.sys
    VIA StorX RAID Controller Driver - 8.0.9200.8110 [VIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vstxraid.sys
     Promiser SuperTrak EX Series -  5.1.0000.10 [Promise Technology, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\stexstor.sys
    Chelsio Communications iSCSI Controller - 10.0.10011.16384 [Chelsio Communications]: \\.\GLOBALROOT\SystemRoot\System32\drivers\cht4sx64.sys
    Intel(R) Rapid Storage Technology driver (inbox) - 15.44.0.1015 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\iaStorAVC.sys
    PMC-Sierra HBA Controller - 1.3.0.10769 [PMC-Sierra]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ADP80XX.SYS
    Smart Array SAS/SATA Controller Media Driver - 8.0.4.0 Build 1 Media Driver (x86-64) [Hewlett-Packard Company]: \\.\GLOBALROOT\SystemRoot\System32\drivers\HpSAMD.sys
    VMware PVSCSI StorPort driver (64-bit) - 1.3.28.0 build-24083437 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\pvscsi.sys
    SmartRAID, SmartHBA PQI Storport Driver - 1.50.1.0 [Microsemi Corportation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\SmartSAMD.sys
    VMware Guest Introspection Driver - 12.5.0.0 build-24139817 [Broadcom Inc. and/or its subsidiaries.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vsepflt.sys
    VMware Raw Disk Helper Driver - 1.1.8.0 build-24049250 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vmrawdsk.sys
    VMware Guest Introspection WFP Network Filter Driver - 12.5.0.0 build-24139817 [Broadcom Inc. and/or its subsidiaries.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vnetWFP.sys
    VMware Pointing PS/2 Device Driver - 12.5.14.0 build-24049250 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmmouse.sys
    VMware SVGA 3D - 9.17.09.0004 - build-24449046 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\System32\DriverStore\FileRepository\vm3d.inf_amd64_eba3f0b96d8538e4\vm3dmp_loader.sys
    VMware SVGA 3D - 9.17.09.0004 - build-24449046 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\System32\DriverStore\FileRepository\vm3d.inf_amd64_eba3f0b96d8538e4\vm3dmp.sys
    VMware server memory controller - 7.5.9.0 build-24049250 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vmmemctl.sys
    VMware PCIe Ethernet Adapter NDIS 6.85 (64-bit) - 1.9.20.0 build-24409624 [Broadcom Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmxnet3.sys
    Intel(R) Gigabit Adapter - 12.18.9.23 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\e1i68x64.sys


�����������������������������������͹ Network Information �������������������������������������

����������͹ Network Shares
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )

����������͹ Enumerate Network Mapped Drives (WMI)

����������͹ Host File

����������͹ Network Ifaces and known hosts
� The masks are only for the IPv4 addresses
    Ethernet0[00:50:56:8A:EB:DA]: 192.168.104.206 / 255.255.255.0
        Gateways: 192.168.104.254
        Known hosts:
          192.168.104.254       00-50-56-8A-C5-9B     Dynamic
          192.168.104.255       FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static

    Ethernet1 2[00:50:56:8A:95:6B]: 172.16.104.206, fe80::899:1fa6:db40:7bb9%19 / 255.255.255.0
        DNSs: 172.16.104.200
        Known hosts:
          172.16.104.200        00-50-56-8A-F1-C7     Dynamic
          172.16.104.202        00-50-56-8A-4F-29     Dynamic
          172.16.104.255        FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static
          255.255.255.255       FF-FF-FF-FF-FF-FF     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static
          239.255.255.250       00-00-00-00-00-00     Static


����������͹ Current TCP Listening Ports
� Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               21            0.0.0.0               0               Listening         6212            c:\xampp\filezillaftp\filezillaserver.exe
  TCP        0.0.0.0               80            0.0.0.0               0               Listening         1976            C:\xampp\apache\bin\httpd.exe
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         452             C:\Windows\system32\svchost.exe
  TCP        0.0.0.0               443           0.0.0.0               0               Listening         1976            C:\xampp\apache\bin\httpd.exe
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               3306          0.0.0.0               0               Listening         3204            C:\xampp\mysql\bin\mysqld.exe
  TCP        0.0.0.0               3389          0.0.0.0               0               Listening         1148            C:\Windows\System32\svchost.exe
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         6548            C:\Windows\system32\svchost.exe
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         808             C:\Windows\system32\lsass.exe
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         640             wininit
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         2112            C:\Windows\System32\svchost.exe
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         2152            C:\Windows\system32\svchost.exe
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         2468            C:\Windows\System32\svchost.exe
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         808             C:\Windows\system32\lsass.exe
  TCP        0.0.0.0               49670         0.0.0.0               0               Listening         760             services
  TCP        127.0.0.1             14147         0.0.0.0               0               Listening         6212            c:\xampp\filezillaftp\filezillaserver.exe
  TCP        172.16.104.206        139           0.0.0.0               0               Listening         4               System
  TCP        172.16.104.206        57581         172.16.104.200        49668           Established       808             C:\Windows\system32\lsass.exe
  TCP        192.168.104.206       80            192.168.49.104        45240           Close Wait        1976            C:\xampp\apache\bin\httpd.exe
  TCP        192.168.104.206       80            192.168.49.104        50012           Close Wait        1976            C:\xampp\apache\bin\httpd.exe
  TCP        192.168.104.206       80            192.168.49.104        56896           Close Wait        1976            C:\xampp\apache\bin\httpd.exe
  TCP        192.168.104.206       139           0.0.0.0               0               Listening         4               System
  TCP        192.168.104.206       3389          192.168.49.104        49042           Established       1148            C:\Windows\System32\svchost.exe
  TCP        192.168.104.206       57550         192.168.49.104        443             Established       252             c:\xampp\rev.exe
  TCP        192.168.104.206       57603         192.168.49.104        443             Established       6680            c:\xampp\rev.exe

  Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        21            [::]                                        0               Listening         6212            c:\xampp\filezillaftp\filezillaserver.exe
  TCP        [::]                                        80            [::]                                        0               Listening         1976            C:\xampp\apache\bin\httpd.exe
  TCP        [::]                                        135           [::]                                        0               Listening         452             C:\Windows\system32\svchost.exe
  TCP        [::]                                        443           [::]                                        0               Listening         1976            C:\xampp\apache\bin\httpd.exe
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        3306          [::]                                        0               Listening         3204            C:\xampp\mysql\bin\mysqld.exe
  TCP        [::]                                        3389          [::]                                        0               Listening         1148            C:\Windows\System32\svchost.exe
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        47001         [::]                                        0               Listening         4               System
  TCP        [::]                                        49664         [::]                                        0               Listening         808             C:\Windows\system32\lsass.exe
  TCP        [::]                                        49665         [::]                                        0               Listening         640             wininit
  TCP        [::]                                        49666         [::]                                        0               Listening         2112            C:\Windows\System32\svchost.exe
  TCP        [::]                                        49667         [::]                                        0               Listening         2152            C:\Windows\system32\svchost.exe
  TCP        [::]                                        49668         [::]                                        0               Listening         2468            C:\Windows\System32\svchost.exe
  TCP        [::]                                        49669         [::]                                        0               Listening         808             C:\Windows\system32\lsass.exe
  TCP        [::]                                        49670         [::]                                        0               Listening         760             services
  TCP        [::1]                                       14147         [::]                                        0               Listening         6212            c:\xampp\filezillaftp\filezillaserver.exe
  TCP        [fe80::899:1fa6:db40:7bb9%19]               135           [fe80::899:1fa6:db40:7bb9%19]               57632           Established       452             C:\Windows\system32\svchost.exe
  TCP        [fe80::899:1fa6:db40:7bb9%19]               49666         [fe80::899:1fa6:db40:7bb9%19]               57633           Established       2112            C:\Windows\System32\svchost.exe
  TCP        [fe80::899:1fa6:db40:7bb9%19]               57632         [fe80::899:1fa6:db40:7bb9%19]               135             Established       2780            C:\Users\Administrator\Desktop\winPEASx64.exe
  TCP        [fe80::899:1fa6:db40:7bb9%19]               57633         [fe80::899:1fa6:db40:7bb9%19]               49666           Established       2780            C:\Users\Administrator\Desktop\winPEASx64.exe

����������͹ Current UDP Listening Ports
� Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        0.0.0.0               123           *:*                            1244              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               3389          *:*                            1148              C:\Windows\System32\svchost.exe
  UDP        0.0.0.0               5050          *:*                            6548              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               5353          *:*                            11152             C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  UDP        0.0.0.0               5353          *:*                            11152             C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  UDP        0.0.0.0               5353          *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               5353          *:*                            11152             C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  UDP        0.0.0.0               5355          *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               54623         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               59642         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               59730         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        0.0.0.0               60269         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        127.0.0.1             1900          *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        127.0.0.1             49664         *:*                            2796              C:\Windows\System32\svchost.exe
  UDP        127.0.0.1             53574         *:*                            2780              C:\Users\Administrator\Desktop\winPEASx64.exe
  UDP        127.0.0.1             54704         *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        127.0.0.1             60392         *:*                            7936              C:\Users\Administrator\Desktop\winPEASx64.exe
  UDP        127.0.0.1             62062         *:*                            808               C:\Windows\system32\lsass.exe
  UDP        127.0.0.1             62218         *:*                            1484              C:\Windows\System32\svchost.exe
  UDP        172.16.104.206        137           *:*                            4                 System
  UDP        172.16.104.206        138           *:*                            4                 System
  UDP        172.16.104.206        1900          *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        172.16.104.206        54703         *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        192.168.104.206       137           *:*                            4                 System
  UDP        192.168.104.206       138           *:*                            4                 System
  UDP        192.168.104.206       1900          *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        192.168.104.206       54702         *:*                            5976              C:\Windows\system32\svchost.exe

  Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        [::]                                        123           *:*                            1244              C:\Windows\system32\svchost.exe
  UDP        [::]                                        3389          *:*                            1148              C:\Windows\System32\svchost.exe
  UDP        [::]                                        5353          *:*                            11152             C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  UDP        [::]                                        5353          *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        [::]                                        5355          *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        [::]                                        54623         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        [::]                                        59642         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        [::]                                        59730         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        [::]                                        60269         *:*                            1504              C:\Windows\system32\svchost.exe
  UDP        [::1]                                       1900          *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        [::1]                                       54701         *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        [fe80::899:1fa6:db40:7bb9%19]               1900          *:*                            5976              C:\Windows\system32\svchost.exe
  UDP        [fe80::899:1fa6:db40:7bb9%19]               54700         *:*                            5976              C:\Windows\system32\svchost.exe

����������͹ Firewall Rules
� Showing only DENY rules (too many ALLOW rules always)
    Current Profiles: DOMAIN, PUBLIC
    FirewallEnabled (Domain):    True
    FirewallEnabled (Private):    True
    FirewallEnabled (Public):    True
    DENY rules:
  [X] Exception: Object reference not set to an instance of an object.
    (5)FileZilla Server[C:\xampp\filezillaftp\filezillaserver.exe]: DENY UDP IN from *:* --> *:*
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Folder Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    FileZilla Server
    (5)FileZilla Server[C:\xampp\filezillaftp\filezillaserver.exe]: DENY TCP IN from *:* --> *:*
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Folder Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    FileZilla Server
    (5)Mercury/32 Core Processing Module v4.62[C:\xampp\mercurymail\mercury.exe]: DENY UDP IN from *:* --> *:*
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Folder Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Mercury/32 Core Processing Module v4.62
    (5)Mercury/32 Core Processing Module v4.62[C:\xampp\mercurymail\mercury.exe]: DENY TCP IN from *:* --> *:*
    File Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Folder Permissions: Administrators [Allow: AllAccess], SYSTEM [Allow: AllAccess], Authenticated Users [Allow: WriteData/CreateFiles]
    Mercury/32 Core Processing Module v4.62

����������͹ DNS cached --limit 70--
    Entry                                 Name                                  Data
    dc20.oscp.exam                        DC20.oscp.exam                        172.16.104.200

����������͹ Enumerating Internet settings, zone and proxy configuration
  General Settings
  Hive        Key                                       Value
  HKCU        User Agent                                Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU        IE5_UA_Backup_Flag                        5.0
  HKCU        ZonesSecurityUpgrade                      System.Byte[]
  HKCU        EnableNegotiate                           1
  HKCU        ProxyEnable                               0
  HKCU        MigrateProxy                              1
  HKLM        ActiveXCache                              C:\Windows\Downloaded Program Files
  HKLM        CodeBaseSearchPath                        CODEBASE
  HKLM        EnablePunycode                            1
  HKLM        MinorVersion                              0
  HKLM        WarnOnIntranet                            1

  Zone Maps
  No URLs configured

  Zone Auth Settings
  No Zone Auth Settings

����������͹ Internet Connectivity
� Checking if internet access is possible via different methods
    HTTP (80) Access: Not Accessible
  [X] Exception:       Error: A task was canceled.
    HTTPS (443) Access: Not Accessible
  [X] Exception:       Error: TCP connect timed out
    HTTPS (443) Access by Domain Name: Not Accessible
  [X] Exception:       Error: A task was canceled.
    DNS (53) Access: Not Accessible
  [X] Exception:       Error: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond
    ICMP (ping) Access: Not Accessible
  [X] Exception:       Error: Ping failed: TimedOut

����������͹ Hostname Resolution
� Checking if the hostname can be resolved externally
  [X] Exception:     Error during hostname check: An error occurred while sending the request.


�����������������������������������͹ Active Directory Quick Checks �������������������������������������

����������͹ gMSA readable managed passwords
� Look for Group Managed Service Accounts you can read (msDS-ManagedPassword) https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/gmsa.html
  [-] No gMSA with readable managed password found (checked 0).

����������͹ AD CS misconfigurations for ESC
�  https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates.html
� Check for ADCS misconfigurations in the local DC registry
  [-] Host is not a domain controller. Skipping ADCS Registry check
�
If you can modify a template (WriteDacl/WriteOwner/GenericAll), you can abuse ESC4
  [-] No templates with dangerous rights found (checked 0).


�����������������������������������͹ Cloud Information �������������������������������������
Learn and practice cloud hacking in training.hacktricks.xyz
AWS EC2?                                No
Azure VM?                               No
Azure Tokens?                           No
Google Cloud Platform?                  No
Google Workspace Joined?                No
Google Cloud Directory Sync?            No
Google Password Sync?                   No


�����������������������������������͹ Windows Credentials �������������������������������������

����������͹ Checking Windows Vault
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault
    Not Found

����������͹ Checking Credential manager
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault
    [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string


  [!] Unable to enumerate credentials automatically, error: 'Win32Exception: System.ComponentModel.Win32Exception (0x80004005): Element not found'
Please run:
cmdkey /list

����������͹ Saved RDP connections
    Not Found

����������͹ Remote Desktop Server/Client Settings
  RDP Server Settings
    Network Level Authentication            :
    Block Clipboard Redirection             :
    Block COM Port Redirection              :
    Block Drive Redirection                 :
    Block LPT Port Redirection              :
    Block PnP Device Redirection            :
    Block Printer Redirection               :
    Allow Smart Card Redirection            :

  RDP Client Settings
    Disable Password Saving                 :       True
    Restricted Remote Administration        :       False

����������͹ Recently run commands
    Not Found

����������͹ Checking for DPAPI Master Keys
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    Not Found

����������͹ Checking for DPAPI Credential Files
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    CredFile: C:\Users\Administrator\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: 4db8dc0d-1b31-4be7-8434-f7019b7fe198
    Accessed: 5/1/2026 12:16:49 PM
    Modified: 5/1/2026 12:16:46 PM
    Size: 11152
   =================================================================================================

� Follow the provided link for further instructions in how to decrypt the creds file

����������͹ Checking for RDCMan Settings Files
� Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#remote-desktop-credential-manager
    Not Found

����������͹ Looking for Kerberos tickets
�  https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-kerberos-88/index.html
    [*] Enumerated 5 ticket(s):

    [*] Enumerated 6 ticket(s):

    [*] Enumerated 8 ticket(s):

    UserPrincipalName: r.andrews@OSCP.EXAM
    serverName: krbtgt/OSCP.EXAM
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 2:01:08 PM
    EndTime: 8/23/2026 12:01:07 AM
    RenewTime: 8/29/2026 2:01:07 PM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwarded, forwardable
   =================================================================================================

    UserPrincipalName: r.andrews@OSCP.EXAM
    serverName: krbtgt/OSCP.EXAM
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 2:01:07 PM
    EndTime: 8/23/2026 12:01:07 AM
    RenewTime: 8/29/2026 2:01:07 PM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, initial, renewable, forwardable
   =================================================================================================

    UserPrincipalName: r.andrews@OSCP.EXAM
    serverName: ProtectedStorage/DC20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 2:01:08 PM
    EndTime: 8/23/2026 12:01:07 AM
    RenewTime: 8/29/2026 2:01:07 PM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: r.andrews@OSCP.EXAM
    serverName: cifs/DC20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 2:01:08 PM
    EndTime: 8/23/2026 12:01:07 AM
    RenewTime: 8/29/2026 2:01:07 PM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: r.andrews@OSCP.EXAM
    serverName: LDAP/DC20.oscp.exam/oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 2:01:08 PM
    EndTime: 8/23/2026 12:01:07 AM
    RenewTime: 8/29/2026 2:01:07 PM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName:
    serverName: krbtgt/OSCP.EXAM
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:42 AM
    EndTime: 8/22/2026 5:52:36 PM
    RenewTime: 8/29/2026 7:52:36 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwarded, forwardable
   =================================================================================================

    UserPrincipalName:
    serverName: krbtgt/OSCP.EXAM
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:36 AM
    EndTime: 8/22/2026 5:52:36 PM
    RenewTime: 8/29/2026 7:52:36 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, initial, renewable, forwardable
   =================================================================================================

    UserPrincipalName:
    serverName: cifs/DC20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:53:33 AM
    EndTime: 8/22/2026 5:52:36 PM
    RenewTime: 8/29/2026 7:52:36 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName:
    serverName: DNS/dc20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:42 AM
    EndTime: 8/22/2026 5:52:36 PM
    RenewTime: 8/29/2026 7:52:36 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName:
    serverName: ldap/dc20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:36 AM
    EndTime: 8/22/2026 5:52:36 PM
    RenewTime: 8/29/2026 7:52:36 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName:
    serverName: ldap/dc20.oscp.exam/oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:36 AM
    EndTime: 8/22/2026 5:52:36 PM
    RenewTime: 8/29/2026 7:52:36 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: krbtgt/OSCP.EXAM
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:53:37 AM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwarded, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: krbtgt/OSCP.EXAM
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:37 AM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, initial, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: cifs/DC20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 4:49:41 PM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: cifs/DC20.oscp.exam/oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:53:37 AM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: WS26$
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:53:37 AM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: LDAP/DC20.oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:43 AM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: ldap/DC20.oscp.exam/oscp.exam
    RealmName: OSCP.EXAM
    StartTime: 8/22/2026 7:52:37 AM
    EndTime: 8/22/2026 5:52:37 PM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    UserPrincipalName: WS26$@oscp.exam
    serverName: ws26$
    RealmName:
    StartTime: 8/22/2026 8:10:30 AM
    EndTime: 8/22/2026 8:25:30 AM
    RenewTime: 8/29/2026 7:52:37 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwardable
   =================================================================================================


����������͹ Looking for saved Wifi credentials
  [X] Exception: The service has not been started
Enumerating WLAN using wlanapi.dll failed, trying to enumerate using 'netsh'
No saved Wifi credentials found

����������͹ Looking AppCmd.exe
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#appcmdexe
    Not Found

����������͹ Looking SSClient.exe
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#scclient--sccm
    Not Found

����������͹ Enumerating SSCM - System Center Configuration Manager settings

����������͹ Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    WS26$::OSCP:1122334455667788:66480a51f1f349021ba2d71b2ce352fd:0101000000000000e1fc36089332dd01d8b240524c47986300000000080030003000000000000000000000000040000000ffb5f58534f86368420f5e2b1bfa6a6fc7ef94b98e4ba66d0e4f8b3661041b0a00100000000000000000000000000000000000090000000000000000000000

   =================================================================================================



�����������������������������������͹ Browsers Information �������������������������������������

����������͹ Showing saved credentials for Firefox
    Info: if no credentials were listed, you might need to close the browser and try again.

����������͹ Looking for Firefox DBs
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Not Found

����������͹ Looking for GET credentials in Firefox history
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Not Found

����������͹ Showing saved credentials for Chrome
    Info: if no credentials were listed, you might need to close the browser and try again.

����������͹ Looking for Chrome DBs
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Not Found

����������͹ Looking for GET credentials in Chrome history
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history


=== Chrome (All Users) ===
    Not Found

����������͹ Chrome bookmarks
    Not Found

����������͹ Showing saved credentials for Opera
    Info: if no credentials were listed, you might need to close the browser and try again.

����������͹ Showing saved credentials for Brave Browser
    Info: if no credentials were listed, you might need to close the browser and try again.

����������͹ Showing saved credentials for Internet Explorer (unsupported)
    Info: if no credentials were listed, you might need to close the browser and try again.

����������͹ Current IE tabs
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Not Found

����������͹ Looking for GET credentials in IE history
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history


����������͹ IE history -- limit 50

    http://go.microsoft.com/fwlink/p/?LinkId=255142
    http://go.microsoft.com/fwlink/p/?LinkId=255142

����������͹ IE favorites
    Not Found


�����������������������������������͹ Interesting files and registry �������������������������������������

����������͹ Putty Sessions


=== Putty Saved Session Information (All Users) ===

    Not Found

����������͹ Putty SSH Host keys


=== Putty SSH Host Hosts (All Users) ===

    Not Found

����������͹ SSH keys in registry
� If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#ssh-keys-in-registry
    Not Found

����������͹ SuperPutty configuration files

����������͹ Enumerating Office 365 endpoints synced by OneDrive.

    SID: S-1-5-19
   =================================================================================================

    SID: S-1-5-20
   =================================================================================================

    SID: S-1-5-21-1010576050-2316036354-870063271-1120
      Name:  Personal
        UserFolder                                 C:\Users\r.andrews\OneDrive
   =================================================================================================

    SID: S-1-5-18
   =================================================================================================


����������͹ Cloud Credentials
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials
    Not Found

����������͹ Unattend Files

����������͹ Looking for common SAM & SYSTEM backups

����������͹ Looking for McAfee Sitelist.xml Files

����������͹ Cached GPP Passwords

����������͹ Looking for possible regs with creds
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#inside-the-registry
    Not Found
    Not Found
    Not Found
    Not Found

����������͹ Looking for possible password files in users homes
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials
    C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.2.0.0\passwords.txt
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

����������͹ Searching for Oracle SQL Developer config files


����������͹ Slack files & directories
  note: check manually if something is found

����������͹ Looking for LOL Binaries and Scripts (can be slow)
�  https://lolbas-project.github.io/
   [!] Check skipped, if you want to run it, please specify '-lolbas' argument

����������͹ Enumerating Outlook download files


����������͹ Enumerating machine and user certificate files


����������͹ Searching known files that can contain creds in home
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials

����������͹ Looking for documents --limit 100--
    Not Found

����������͹ Office Most Recent Files -- limit 50

  Last Access Date           User                                           Application           Document

����������͹ Recent files --limit 70--
   Administrator :

   r.andrews :

    C:\xampp\phpMyAdmin\config.inc.php(8/22/2026 2:25:32 PM)
    C:\xampp\FileZillaFTP\FileZilla Server.xml(8/22/2026 2:25:21 PM)
    C:\xampp\FileZillaFTP(8/22/2026 2:25:21 PM)
    C:\xampp\htdocs(8/22/2026 2:11:42 PM)
    C:\xampp\php(8/22/2026 2:26:14 PM)
    C:\xampp\php\php.ini(8/22/2026 2:26:14 PM)
    C:\xampp\phpMyAdmin(8/22/2026 2:25:32 PM)
    C:\xampp\htdocs\submit-ticket.php(8/22/2026 2:11:42 PM)

����������͹ Looking inside the Recycle Bin for creds files
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials
    Not Found

����������͹ Searching hidden files or folders in C:\Users home (can be slow)

     C:\Users\Default User
     C:\Users\Default
     C:\Users\All Users
     C:\Users\Default
     C:\Users\All Users

����������͹ Searching interesting files in other users home directories (can be slow)

     You are already Administrator, check users home folders manually.

����������͹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\xampp\php\phpunit.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\phpdbg.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\php.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\php-win.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\php-cgi.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\pecl.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\peardev.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\pear.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\pciconf.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\pci.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\deplister.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\windowsXamppPhp\deplister.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\windowsXamppPhp\php-cgi.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\windowsXamppPhp\php-win.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\windowsXamppPhp\php.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\windowsXamppPhp\phpdbg.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\scripts\pciconf.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\scripts\compatinfo.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\php\extras\openssl\openssl.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\makecert.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\apache_uninstallservice.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\apache_installservice.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\scripts\ctl.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\wintty.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\rotatelogs.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\pv.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\openssl.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\logresolve.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\httxt2dbm.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\httpd.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\htpasswd.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\htdigest.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\htdbm.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\htcacheclean.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\curl.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\ApacheMonitor.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\abs.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache\bin\ab.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\FileZillaFTP\Uninstall.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\FileZillaFTP\FileZillaServer.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\FileZillaFTP\FileZilla server.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\FileZillaFTP\FileZilla Server Interface.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\sendmail\sendmail.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\src\xampp-usb-lite\setup_xampp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\src\xampp-usb-lite\make-usb-xampp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\src\xampp-nsi-installer\xa-icons\portcheck.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache_start.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\apache_stop.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\catalina_service.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\catalina_start.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\catalina_stop.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\ctlscript.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\filezilla_setup.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\filezilla_start.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\filezilla_stop.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\killprocess.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\mercury_start.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\mercury_stop.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\mysql_start.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\mysql_stop.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\rev.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\service.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\setup_xampp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\test_php.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\uninstall.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\xampp-control.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\xampp_shell.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\xampp_start.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\xampp_stop.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\install\awk.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\install\portcheck.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\tomcat_service_uninstall.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\tomcat_service_install.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\catalina_stop.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\catalina_start.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\version.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\tool-wrapper.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\tomcat8w.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\tomcat8.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\startup.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\shutdown.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\setclasspath.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\service.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\digest.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\configtest.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\ciphers.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\tomcat\bin\catalina.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\webalizer\wcmgr.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\webalizer\webalizer.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\webalizer\webalizer.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\mailtodisk\mailtodisk.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\wssetup.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\wsendto.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\wpmmapi.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\winpm-32.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\urlproxy.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\unins000.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\sqlite3.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\setreg.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\setpmdefault.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\pmsort.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\pmgrant.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\pconfig.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\newmail.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\msendto.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\mercury.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\mbxmaint_ui.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\mbxmaint.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\malias.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\loader.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\limits.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\fsynonym.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\desetup2.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\desetup.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\RESOURCE\rescom.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\DAEMONS\spamhaltersetup.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\DAEMONS\graywallsetup.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\MercuryMail\DAEMONS\clamwallsetup.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\mysql\resetroot.bat": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\mysql_uninstallservice.bat": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\mysql_installservice.bat": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\scripts\ctl.bat": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\sst_dump.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\replace.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\perror.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\my_print_defaults.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_upgrade_wizard.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_upgrade_service.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_upgrade.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_tzinfo_to_sql.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_plugin.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_ldb.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql_install_db.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqlslap.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqlshow.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqlimport.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqldump.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqld.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqlcheck.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqlbinlog.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysqladmin.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mysql.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\myisam_ftdump.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\myisampack.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\myisamlog.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\myisamchk.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mbstream.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\mariabackup.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\innochecksum.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\aria_read_log.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\aria_pack.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\aria_ftdump.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\aria_dump_log.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\mysql\bin\aria_chk.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\xampp\perl\bin\zipdetails.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\xsubpp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\xml_split.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\xml_spellcheck.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\xml_pp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\xml_merge.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\xml_grep.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\wperl.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\whirlpoolsum.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\use-devel-checklib.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\ttree.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\tpage.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\test-yaml.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\stubmaker.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\streamzip.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\splain.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\SOAPsh.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\shasum.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\search.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\scan-perl-prereqs-nqlite.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\runperl.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\ptargrep.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\ptardiff.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\ptar.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\prove.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\primes.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\ppm.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\ppd2par.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pod_cover.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\podselect.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\podchecker.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pod2usage.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pod2text.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pod2man.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pod2latex.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pod2html.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pm-uninstall.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pler.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pl2pm.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pl2bat.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pkg-config.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\piconv.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\pgplet.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perltidy.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perlthanks.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perlivp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perlglob.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perlglob.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perldoc.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perlbug.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\perl.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\parinstallppd.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\package-stash-conflicts.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\nssm_64.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\nssm_32.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\mymeta-cpanfile.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\morbo.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\moose-outdated.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\mojo.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\module-version.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\minicpan.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\mech-dump.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\lwp-request.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\lwp-mirror.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\lwp-dump.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\lwp-download.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\llw32helper.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\libnetcfg.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\kwalitee-metrics.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\json_xs.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\json_pp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\instmodsh.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\hypnotoad.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\htmltree.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\h2xs.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\h2ph.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\findrule.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\factor.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\extract_vba.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\exe_update.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\exetype.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\encguess.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\enc2xs.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\dbiproxy.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\dbiprof.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\dbilogstrip.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\dbicadmin.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\crc32.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpanp.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpanp-run-perl.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpanm.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpanfile-dump.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpanel_json_xs.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpandb.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpan2dist.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpan.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpan-outdated.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\cpan-mirrors.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\corelist.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\config_data.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\chartex.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\bin\bdf2gdfont.bat": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\xampp\perl\vendor\lib\auto\share\dist\FFI-Platypus\probe\bin\dlrun.exe": Administrators [Allow: AllAccess],SYSTEM [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\Users\Administrator\Desktop\winPEASx64.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\Desktop\mimikatz.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\Desktop\agent.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\OneDrive.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\XboxPcAppCE.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\XboxPcAppAdminServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\wt.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\winget.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerMCPServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\store.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\SnippingTool.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\python3.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\python.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\pbrush.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\notepad.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\msteams_autostarter.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\msteamsupdate.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\msteams.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\mspaint.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\microsoftstore.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MediaPlayer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\GetHelp.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteams_autostarter.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteamsupdate.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteams.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.ZuneMusic_8wekyb3d8bbwe\MediaPlayer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsTerminal_8wekyb3d8bbwe\wt.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsStore_8wekyb3d8bbwe\store.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsStore_8wekyb3d8bbwe\microsoftstore.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsNotepad_8wekyb3d8bbwe\notepad.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.ScreenSketch_8wekyb3d8bbwe\SnippingTool.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.Paint_8wekyb3d8bbwe\pbrush.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.Paint_8wekyb3d8bbwe\mspaint.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.GetHelp_8wekyb3d8bbwe\GetHelp.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.GamingApp_8wekyb3d8bbwe\XboxPcAppCE.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.GamingApp_8wekyb3d8bbwe\XboxPcAppAdminServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerMCPServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\All Users\Microsoft\Windows Defender\Scans\MsMpEngCP.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\XboxPcAppCE.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\XboxPcAppAdminServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\wt.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\winget.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerMCPServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\store.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\SnippingTool.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\python3.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\python.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\pbrush.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\notepad.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\msteams_autostarter.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\msteamsupdate.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\msteams.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\mspaint.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\microsoftstore.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\MediaPlayer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\GetHelp.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteams_autostarter.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteamsupdate.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteams.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.ZuneMusic_8wekyb3d8bbwe\MediaPlayer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsTerminal_8wekyb3d8bbwe\wt.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsStore_8wekyb3d8bbwe\store.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsStore_8wekyb3d8bbwe\microsoftstore.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsNotepad_8wekyb3d8bbwe\notepad.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.ScreenSketch_8wekyb3d8bbwe\SnippingTool.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.Paint_8wekyb3d8bbwe\pbrush.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.Paint_8wekyb3d8bbwe\mspaint.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.GetHelp_8wekyb3d8bbwe\GetHelp.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.GamingApp_8wekyb3d8bbwe\XboxPcAppCE.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.GamingApp_8wekyb3d8bbwe\XboxPcAppAdminServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerMCPServer.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\OneDrive.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\CollectSyncLogs.bat": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\FileCoAuth.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\FileSyncConfig.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\FileSyncHelper.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\Microsoft.Nucleus.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\Microsoft.Nucleus.NativeMessagingClient.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\OneDriveFileLauncher.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\OneDriveSetup.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Users\r.andrews\AppData\Local\Microsoft\OneDrive\21.050.0310.0001\OneDriveUpdaterService.exe": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]
     File Permissions "C:\Recovery\OEM\AfterImageApply_BDB0C1E8-6951-46C4-AB7F-C07B29F462FD.cmd": SYSTEM [Allow: AllAccess],Administrators [Allow: AllAccess]

����������͹ Looking for Linux shells/distributions - wsl.exe, bash.exe
    C:\Windows\System32\wsl.exe

    WSL - no installed Linux distributions found.

       /---------------------------------------------------------------------------------\
       |                             Do you like PEASS?                                  |
       |---------------------------------------------------------------------------------|
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |
       |         Follow on Twitter         :     @hacktricks_live                        |
       |         Respect on HTB            :     SirBroccoli                             |
       |---------------------------------------------------------------------------------|
       |                                 Thank you!                                      |
       \---------------------------------------------------------------------------------/
```