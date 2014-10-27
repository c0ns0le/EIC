powershell.exe set-executionpolicy bypass -force
>c:\deploy\flow.txt echo w7client
schtasks.exe /CREATE /RU "BUILTIN\users" /SC ONLOGON /RL HIGHEST /TN "EIC" /tr "powershell.exe -noexit -file c:\deploy\Setup.ps1"
powershell -noexit -file .\setup.ps1
