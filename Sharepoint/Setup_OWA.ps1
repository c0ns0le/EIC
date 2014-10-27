$Install_SP2013_OWA_Scriptblock = {

Add-WindowsFeature Web-Server,Web-Mgmt-Tools,Web-Mgmt-Console,Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Static-Content,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression,Web-Security,Web-Filtering,Web-Windows-Auth,Web-App-Dev,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Includes,InkandHandwritingServices,NET-Framework-Features,NET-Framework-Core
http://download.microsoft.com/download/B/4/1/B4119C11-0423-477B-80EE-7A474314B347/NDP452-KB2901954-Web.exe
http://download.microsoft.com/download/7/7/F/77F250DC-F7A3-47AF-8B20-DDA8EE110AB4/wacserver.img
http://download.microsoft.com/download/F/E/2/FE25F2E9-BECB-424E-B8B3-BB377112A191/wacserversp2013-kb2880558-fullfile-x64-glb.exe


New-OfficeWebAppsFarm -InternalUrl "https://wacs.$DomainName" -ExternalUrl "https://wacs.$DomainName" -CertificateName "OfficeWebApps Certificate" -EditingEnabled

