@echo off
taskkill /f /im polipo.exe
schtasks /run "Polipo Proxy"
echo If this gave you errors, you should have right-clicked on it and clicked "Run As Administrator"
pause
