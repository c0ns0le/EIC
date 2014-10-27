@echo off

:start
if exist d:\Setup\amd64\Setup2.exe (
	mkdir c:\LyncMedia
	xcopy d:\* c:\LyncMedia /e /y /q
	) else (
	echo Please insert the Lync 2013 SP1 CD into drive D.
	pause
	goto :start
	)
@echo on
powershell.exe set-executionpolicy bypass -force
>c:\deploy\flow.txt echo Lync2013Std
schtasks.exe /CREATE /F /RU "BUILTIN\users" /SC ONLOGON /RL HIGHEST /TN "EIC" /tr "powershell.exe -noexit -file c:\deploy\Setup.ps1"
powershell -noexit -file .\setup.ps1