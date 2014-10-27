powershell.exe set-executionpolicy bypass -force
powershell -noexit -ex bypass .\setup.ps1 -stage SP2013_PostInstall
