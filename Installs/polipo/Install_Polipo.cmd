mkdir c:\polipo
Copy c:\deploy\installs\polipo c:\polipo
REM schtasks /create /ru "NT AUTHORITY\NETWORKSERVICE" /sc ONSTART /tn "Polipo Proxy" /tr "C:\polipo\polipo.exe -c c:/polipo/config.conf"
schtasks /create /tn "Polipo Proxy" /xml .\polipotask.xml /f
schtasks /run /tn "Polipo Proxy"
