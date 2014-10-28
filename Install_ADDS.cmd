powershell.exe set-executionpolicy bypass -force
>c:\deploy\flow.txt echo adds
schtasks.exe /CREATE /RU "BUILTIN\users" /SC ONLOGON /RL HIGHEST /TN "EIC" /tr "powershell.exe -noexit -file c:\deploy\Setup.ps1" /F
powershell -noexit -file .\setup.ps1
