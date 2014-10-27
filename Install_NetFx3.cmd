@echo off
:start
if exist d:\sources\sxs (
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:d:\sources\sxs
) else (
echo Please insert Server 2012R2 installation media into drive D.
pause
goto :start
)
exit
