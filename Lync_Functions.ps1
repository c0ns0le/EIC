Function AddLyncShare {
	New-Item -Path $LyncShare -ItemType Directory | Out-Null
	$acl = Get-Acl $LyncShare
	$acl.SetAccessRuleProtection($True, $False)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule) | Out-Null
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:UserDomain\$env:UserName","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule) | Out-Null
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.RemoveAccessRule($rule) | Out-Null
	Set-Acl $LyncShare $acl | Out-Null
	New-SmbShare -Description "Lync Server 2013 share" -FullAccess "everyone" -Name "LyncShare" -Path "$LyncShare" | Out-Null
}

Function WaitUntilReady ($Window) {
    write-host "Waiting on $($Window.Name)"
    do {Start-Sleep 3;"."} until ($Window.WindowInteractionState -match "ReadyForUserInteraction")
    }
Function ConfigureLyncCertificates {
    $RestartCertsrvScriptblock = {
        restart-service -ServiceName certsvc 
        do {start-sleep 3} 
        until ((get-service -Name certsvc).status -eq "running")
        }

    Invoke-Command -ComputerName "$(($Env:LogonServer).replace('\\','')).$env:UserDNSDomain" -ScriptBlock $RestartCertsrvScriptblock
    start-sleep 10
    $CertificateRequestSettings = @{
        New = $True
        CA = $CAConfig
        Country = "US" 
        State = "OR" 
        City = "Portland" 
        KeySize = 2048 
        PrivateKeyExportable = $True 
        Organization = $NetBiosName 
        OU = $NetBiosName 
        DomainName = "sip.$DomainName" 
        AllSipDomain = $True
        Verbose = $True
        }
    Request-CSCertificate @CertificateRequestSettings  -FriendlyName "LyncDefault"  -Type Default,WebServicesInternal,WebServicesExternal
    $LyncDefaultCertThumbprint = Get-ChildItem Cert:\LocalMachine\My | ?{ $_.FriendlyName -eq "LyncDefault"} | select -expandproperty Thumbprint
    $SetLyncDefaultCertificateSettings = @{
        Type =  @("Default","WebServicesInternal","WebServicesExternal")
        Thumbprint = $LyncDefaultCertThumbprint 
        Confirm = $false
        }
    Set-CSCertificate @SetLyncDefaultCertificateSettings 
    Start-Service MASTER,REPLICA
    Request-CSCertificate @CertificateRequestSettings -Type OAuthTokenIssuer -FriendlyName "OAuthTokenIssuer"
    $OAuthCertThumbprint = Get-ChildItem Cert:\LocalMachine\My | ?{ $_.FriendlyName -eq "OAuthTokenIssuer"} | select -expandproperty Thumbprint
    $SetOAuthCertificateSettings = @{
        Identity = "Global"
        Type = "OAuthTokenIssuer"
        Thumbprint = $OAuthCertThumbprint 
        Confirm = $false
        }
    Set-CSCertificate @SetOAuthCertificateSettings
    Remove-Item "$env:Temp\CSConfigData.zip" -ErrorAction SilentlyContinue
    Export-CSConfiguration -FileName "$env:Temp\CSConfigData.zip"
    Import-CSConfiguration -LocalStore -FileName "$env:Temp\CSConfigData.zip"
    }

Function InstallPreReqs {
    Write-Output "Installing features..."
    Install-Windowsfeature Web-Server, Web-Static-Content, Web-Default-Doc, Web-Http-Errors, Web-Asp-Net
    Install-Windowsfeature  Web-Net-Ext, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Http-Logging, Web-Log-Libraries
    Install-Windowsfeature Web-Request-Monitor, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-Client-Auth
    Install-WindowsFeature Web-Filtering, Web-Stat-Compression, Web-Dyn-Compression, NET-WCF-HTTP-Activation45
    Install-WindowsFeature Web-Asp-Net45, Web-Mgmt-Tools, Web-Scripting-Tools, Web-Mgmt-Compat, Desktop-Experience
    Install-WindowsFeature Telnet-Client, BITS, Windows-Identity-Foundation
    Reg Add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel" /V "EnableSessionTicket" /D 2 /T REG_DWORD /F
    Write-Output "Installing Silverlight..."
    start-process -filepath $SilverLightFile -ArgumentList "/q /norestart" -Wait
    Write-Output "Installing VCRedist..."
    start-process -filepath "$LyncMedia\Setup\amd64\vcredist_x64.exe" -ArgumentList "/q /norestart" -Wait
    Write-Output "Installing SQL Management Objects"
    start-process -filepath "$LyncMedia\setup\amd64\SharedManagementObjects.msi" -ArgumentList "/q /norestart" -wait
    }
Function EnableLyncUsers {
    foreach ($LyncUser in $LyncUserList) {
        Enable-CSUser -identity (Get-ADUser "$LyncUser").UserPrincipalName -RegistrarPool "$env:computername.$DomainName" -sipaddresstype EmailAddress -SipDomain $DomainName
        }
    }

Function InstallWasp(){
    Copy-Item -Path "$($PowershellModules)\*" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules" -Recurse -Force
    Import-Module WASP
    }

Function InstallLyncUpdates {
    start-process -FilePath $LyncUpdateFile -argumentlist "/SilentMode" -Wait
    }

Function ConfigureLyncUpdates {
    Install-CsDatabase -ConfiguredDatabases -SqlServerFqdn "$env:computername.$env:userdnsdomain" -Verbose
    Install-CsDatabase -CentralManagementDatabase -SqlServerFqdn "$env:computername.$env:userdnsdomain" -SqlInstanceName RTC -Verbose
    Enable-CsTopology
    Start-Process "$Env:ProgramFiles\Microsoft Lync Server 2013\Deployment\Bootstrapper.exe" -wait
    }

Function DeployLync2013Std {   
    InstallSQLExpress "RTCLocal" 
    InstallSQLExpress "LYNCLocal" 
    InstallSQLExpress "RTC"
    AddLyncShare
    Install-Windowsfeature RSAT-ADDS
    InstallPreReqs
    InstallLyncBinaries
    InstallTools
    import-module 'C:\Program Files\Common Files\Microsoft Lync Server 2013\Modules\Lync\Lync.psd1'
    Install-CSAdServerSchema -Confirm:$false -Verbose
    Enable-CSAdForest  -Verbose -Confirm:$false
    Enable-CSAdDomain -Verbose -Confirm:$false 
    DeployTopology
    Add-ADGroupMember "CSAdministrator" -Members "Domain Admins"    
    }

Function DeployLyncRoundTwo {
    InstallServerComponents
    ConfigureLocalManagementStore
    InstallMoreServerComponents
    ConfigureLyncCertificates
    Start-CSWindowsService -NoWait -Verbose
    Invoke-CsManagementStoreReplication
    EnableLyncUsers
    Add-SRVRecord $Env:Computername "_sipinternal._tcp" 5061
    }

###########################################
######## UI Automation Functions ##########
###########################################
Function InstallLyncBinaries {

    #Start-Process -FilePath "msiexec.exe" -ArgumentList " /i C:\LyncMedia\Setup\amd64\Setup\ocscore.msi /qn /norestart" -wait
    #Start-Process -FilePath "MSIExec.exe" -ArgumentList "/i D:\setup\amd64\SQLSysClrTypes.msi /qn" -Wait
    #Start-Process -FilePath "MSIExec.exe" -ArgumentList "/i D:\setup\amd64\setup\admintools.msi /qn" -Wait
    $App = Start-Process -FilePath "$LyncMedia\Setup\amd64\Setup2.exe" -ArgumentList "/sourcedirectory:$LyncMedia\Setup\amd64\" -PassThru
    Start-Sleep 5
    $Process = $App | Select-UIElement -AutomationID "Window_1"
    $Process |  Send-UIKeys "%i"    
    $EULA = Select-UIElement "End User License Agreement" 
    $EULA | Send-UIKeys "%a"
    $EULA | Select-UIElement -AutomationId "Button_2" | Invoke-Invoke.Invoke 
    do {Write-Output "Waiting for Deployment dialog...";start-sleep 3}
    until (Select-UIElement -AutomationID "Window_1")
    $Process = Select-UIElement -AutomationID "Window_1"
    WaitUntilReady $Process
    Start-Sleep 5
    taskkill /f /im deploy.exe
    }

Function InstallTools {
    $App = Start-Process -FilePath  "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe" -PassThru
    do {Write-Output "Waiting for Deployment dialog...";start-sleep 3}
    until (Select-UIElement -AutomationID "Window_1")
    $Process = Select-UIElement -AutomationID "Window_1"
    WaitUntilReady $Process
    $Process |  Send-UIKeys "%t"
    WaitUntilReady $Process
    taskkill /f /im deploy.exe
    }

Function InstallServerComponents {
    $App = Start-Process -FilePath  "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe" -PassThru
    Start-Sleep 1
    do {Write-Output "Waiting for Deployment dialog...";start-sleep 3}
    until (Select-UIElement -AutomationID "Window_1")
 
    $Process = Select-UIElement -AutomationID "Window_1"
    WaitUntilReady $Process
    $Process |  Send-UIKeys "%s"

    do {Write-Output "Waiting for Deployment dialog...";start-sleep 3}
    until ($app | Select-UIElement | Select-UIElement -AutomationId Control)
 
    $ControlWindow = $app | Select-UIElement | Select-UIElement -AutomationId Control
    WaitUntilReady $ControlWindow
    $ControlWindow  |  Send-UIKeys "%n"
    WaitUntilReady $ControlWindow
    $ControlWindow | Send-UIKeys "%f"

    taskkill /f /im deploy.exe
    }


Function ConfigureLocalManagementStore {
    $App = Start-Process -FilePath  "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe" -PassThru
    Start-Sleep 1
    do {Write-Output "Waiting for Deployment dialog...";start-sleep 3}
    until (Select-UIElement -AutomationID "Window_1")
    $Process = Select-UIElement -AutomationID "Window_1"
    WaitUntilReady $Process
    $Process |  Send-UIKeys "%i"
    WaitUntilReady $Process
    $Process |  Send-UIKeys "%i"    
    Start-Sleep 1
    $ControlWindow = Select-UIElement | Select-UIElement -AutomationId Control
    WaitUntilReady $ControlWindow
    $ControlWindow | Send-UIKeys  "%n"
    WaitUntilReady $ControlWindow
    $ControlWindow |  Send-UIKeys "%n"
    WaitUntilReady $ControlWindow
    $ControlWindow |  Send-UIKeys "%f"
    WaitUntilReady $Process
    Taskkill /f /im deploy.exe
    }


Function InstallMoreServerComponents {
    $App = Start-Process -FilePath  "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe" -PassThru
    Start-Sleep 1
    do {Write-Output "Waiting for Deployment dialog...";start-sleep 3}
    until (Select-UIElement -AutomationID "Window_1")
    $Process = Select-UIElement -AutomationID "Window_1"
    WaitUntilReady $Process
    $Process |  Send-UIKeys "%i"    
    WaitUntilReady $Process
    $Process |  Send-UIKeys "%e"
    Start-Sleep 2
    $ControlWindow = Select-UIElement | Select-UIElement -AutomationId Control
    WaitUntilReady $ControlWindow
    $ControlWindow |  Send-UIKeys "%n"
    $FinishButton = $ControlWindow | Select-UIElement -AutomationId "finishButton" -Recurse
    do {start-sleep 3;"."} until ($FinishButton.IsEnabled)
    $ControlWindow |  Send-UIKeys "%f"
    WaitUntilReady $Process
    Taskkill /f /im deploy.exe
    }


Function DeployTopology {
    $App = Start-Process -FilePath "C:\Program Files\Microsoft Lync Server 2013\Administrative Tools\Microsoft.Rtc.Management.TopologyBuilder.exe" -PassThru
    Start-Sleep 5
    Select-UIElement -AutomationId "TopologyBuilderStartupDialogData" -Recurse | Select-UIElement -AutomationId "RadioButton_2"  -Recurse | Invoke-SelectionItem.Select
    Select-UIElement -AutomationId "TopologyBuilderStartupDialogData" -Recurse | Select-UIElement -AutomationId "finishButton"  -Recurse | Invoke-Invoke.Invoke
    $Window = Select-UIElement -name "Lync Server 2013, Topology Builder"
    Start-Sleep 5
    $Window | Select-UIElement "Open" | Send-UIKeys "$TopologyFile"
    $Window | Select-UIElement -ClassName "#32770" | Send-UIKeys "%o"
    $Window | Send-UIKeys "%a"
    Start-Sleep 5
    $Window | Send-UIKeys "p"
    Start-Sleep 5
    $Window | Send-UIKeys "%n"
    do {Write-Output "Waiting for Publish Topology dialog...";start-sleep 3}
    until ($Window | Select-UIElement -Name "Publish Topology" -Recurse)
    $PublishWindow = $Window | Select-UIElement -Name "Publish Topology" -Recurse
    WaitUntilReady $PublishWindow
    $PublishWindow | Send-UIKeys "%n"
    WaitUntilReady $PublishWindow
    $PublishWindow | Send-UIKeys "%n"
    WaitUntilReady $PublishWindow
    $PublishWindow | Send-UIKeys "%F"
    Taskkill /f /im "Microsoft.Rtc.Management.TopologyBuilder.exe"
}
