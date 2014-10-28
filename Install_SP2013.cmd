@echo off
set flow=sp2013

cls
:start
if exist d:\edu.en-us (
	echo Copying Sharepoint files to c:\deploy\sharepoint\2013...
	xcopy d:\* c:\deploy\sharepoint\2013\Sharepoint /e /y /q
	) else (
	echo Please insert the Sharepoint 2013 SP1 CD into drive D.
	pause
	goto :start
	)



@echo on
powershell.exe set-executionpolicy bypass -force
>c:\deploy\flow.txt echo %flow%
schtasks.exe /CREATE /RU "BUILTIN\users" /SC ONLOGON /RL HIGHEST /TN "EIC" /tr "powershell.exe -noexit -file c:\deploy\Setup.ps1" /F
powershell -noexit -file .\setup.ps1