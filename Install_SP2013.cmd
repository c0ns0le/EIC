@echo off
set flow=sp2013

goto :start1

if exist \\vboxsvr\prerequisiteinstallerfiles (
	xcopy \\vboxsvr\prerequisiteinstallerfiles\* C:\deploy\Sharepoint\2013\Sharepoint\prerequisiteinstallerfiles
	) else (
	start /wait c:\deploy\Download_Helper.cmd
	)

:start1
cls
if exist d:\edu.en-us (
	echo Copying Sharepoint files to c:\deploy\sharepoint\2013...
	xcopy d:\* c:\deploy\sharepoint\2013\Sharepoint /e /y /q
	) else (
	echo Please insert the Sharepoint 2013 SP1 CD into drive D.
	pause
	goto :start1
	)
cls
goto :skip
:start2
if exist d:\1033_ENU_LP (
	echo Good! You've got the SQL installation CD in Drive D, leave it there.
	) else (
	echo Please insert the SQL 2012 SP0 CD into drive D.
	pause
	goto :start2
	)

:skip



@echo on
powershell.exe set-executionpolicy bypass -force
>c:\deploy\flow.txt echo %flow%
schtasks.exe /CREATE /RU "BUILTIN\users" /SC ONLOGON /RL HIGHEST /TN "EIC" /tr "powershell.exe -noexit -file c:\deploy\Setup.ps1"
powershell -noexit -file .\setup.ps1