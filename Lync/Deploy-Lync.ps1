$TopologyPath = "c:\deploy\lync\pocketdomain.corp.tbxml"
$LyncMediaPath = "D:"
$CAConfig = "SPDEV-DC.pocketdomain.corp\SPDEV-DC" 
$LyncSharePath = "C:\LyncShare"
$DomainName = "pocketdomain.corp"
$NetBiosName = "pocketdomain"
$InstallPath = "c:\deploy\installs"



add-type -AssemblyName microsoft.VisualBasic
add-type -AssemblyName System.Windows.Forms
function Compile-CSharp (
  [string] $code,
  $frameworkVersion="v2.0.50727",
  [Array] $references
)
{
    $codeProvider = new-object Microsoft.CSharp.CSharpCodeProvider
    $compilerParamerters = New-Object System.CodeDom.Compiler.CompilerParameters
    # Unsafe to compile the code which uses pointers in the DLL call
    $compilerParamerters.CompilerOptions = "-unsafe"
    foreach ($reference in $references) {
      $compilerParamerters.ReferencedAssemblies.Add( $reference );
    }
    $compilerParamerters.GenerateInMemory = $true
    $compilerParamerters.GenerateExecutable = $false
    $compilerParamerters.OutputAssembly = "custom"
    $compiledCode = $codeProvider.CompileAssemblyFromSource(
      $compilerParamerters,
      $code
    )
 
    if ( $compiledCode.Errors.Count)
    {
        $codeLines = $code.Split("`n");
        foreach ($compilerError in $compiledCode.Errors)
        {
            write-host "Error: $($codeLines[$($compilerError.Line - 1)])"
            write-host $compilerError
        }
        throw "Errors encountered while compiling code"
    }
}
$csharp = @'
    using System;
    using System.Windows.Automation;
 
    public static class AutomationHelper
    {
        public static object GetRoot(System.IntPtr mwh)
        {
            return System.Windows.Automation.AutomationElement.FromHandle(
              mwh
            );
        }
    }
'@

function Get-WordFromWindow {
  param ([Windows.Automation.AutomationElement] $element,[boolean]$recurse = $True,[string]$pattern)
  $trueCondition = [Windows.Automation.Condition]::TrueCondition;
  $children = [Windows.Automation.TreeScope]::Children
  if ($element.Current.Name -match $pattern) {$recurse = $false}
  if ($recurse) {
    foreach ($child in $element.FindAll($children, $trueCondition)) {
      if ($child.Current.Name -match $pattern) {
        $recurse = $false 
        break
        }
      Get-WordFromWindow -element $child -recurse $recurse -pattern $pattern
    }
  }
  if (!$recurse) {return !$recurse}
}
Function SpawnWindow ($filepath, $arguments = ""){
    $deploy = [diagnostics.process]::start($filepath, $arguments)
    start-sleep 1
    $mainhandle = $deploy.MainWindowHandle
    $rootElement = [AutomationHelper]::getroot($mainHandle)
    return $rootElement
}
Function WaitForString ($window, $string, $invert = $false){
 if ($invert) {
     do {start-sleep 1;write-host "Waiting for $string..."} 
     until (!(Get-WordFromWindow -element $window -pattern $string))
     } else {
      do {start-sleep 1;write-host "Waiting for $string..."} 
     until (Get-WordFromWindow -element $window -pattern $string)
     }
  }
function tab ($number, $window = $null) {
     if ($window) {$window.SetFocus()}
    for ($i = 0; $i -lt $number; $i++) {
        [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
        Write-Output "tab"
        }
    }
function sendkey ($key, $window = $null) {
    Start-Sleep -Milliseconds 500
    if ($window) {$window.SetFocus()}
    [System.Windows.Forms.SendKeys]::SendWait("$key")
    }
function Activate ($name) {
        do {
            try {write-output "Activating $name..."; Start-Sleep 1; [Microsoft.VisualBasic.Interaction]::AppActivate("$name"); $Result = $True} catch {$Result = $false}
            if ($result -eq $False) {start-sleep 1; Write-Output "Waiting for $name..."}
        } until ($result)
    }
Function AddLyncShare ($LyncSharePath) {
	New-Item -Path $LyncSharePath -ItemType Directory | Out-Null
	$acl = Get-Acl $LyncSharePath
	$acl.SetAccessRuleProtection($True, $False)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule) | Out-Null
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:UserDomain\$env:UserName","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule) | Out-Null
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.RemoveAccessRule($rule) | Out-Null
	Set-Acl $LyncSharePath $acl | Out-Null
	New-SmbShare -Description "Lync Server 2013 share" -FullAccess "everyone" -Name "LyncShare" -Path "$LyncSharePath" | Out-Null
}
Function DeployTopology ($TopologyPath) {
   $Window = SpawnWindow "C:\Program Files\Microsoft Lync Server 2013\Administrative Tools\Microsoft.Rtc.Management.TopologyBuilder.exe"
    sendkey "%O"
    sendkey "{ENTER}" 
    WaitForString $window "Open"
    sendkey $TopologyPath
    sendkey "{ENTER}"
    sendkey "%A"
    sendkey "p"
    WaitForString $window "Publish the topology"
    sendkey "%N"
    WaitForString $window "Select Central Management Server"
    sendkey "%N"
    WaitForString $window "Publishing Wizard Complete"
    sendkey "%F"
    sendkey "%FE" $window 
}
Function InstallTools {
    $window = SpawnWindow "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe"
    WaitforString $window "Determining deployment state" $true
    sendkey "%t" $window 
    start-sleep 60
    taskkill /f /im deploy.exe
    }
function InstallServerComponents {
    $window = SpawnWindow "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe"
    WaitforString $window "Determining deployment state" $true
    sendkey "%s"
    WaitForString $window "Prepare single Standard edition Server"
    sendkey "%n"
    WaitForString $window "Task Status: Completed."
    sendkey "%f"
    taskkill /f /im deploy.exe
    }
Function ConfigureLocalManagementStore {
    $window = SpawnWindow "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe" 
    WaitforString $window "Determining deployment state" $true
    sendkey "%i"
    WaitForString $window "Determining deployment state" $true
    sendkey "%i"
    WaitForString $window "Configure Local Replica of Central Management Store"
    sendkey "%n"
    WaitForString $window "Task Status: Completed."
    sendkey "%f"
    taskkill /f /im deploy.exe
    }
Function InstallMoreServerComponents {
    $window = SpawnWindow "C:\Program Files\Microsoft Lync Server 2013\Deployment\Deploy.exe"
    WaitforString $window "Determining deployment state" $true
    sendkey "%i"
    WaitforString $window "Determining deployment state" $true
    sendkey "%e"
    WaitforString $window "Set Up Lync Server Components"
    sendkey "%n"
    WaitForString $window "Task Status: Completed."
    sendkey "%f"
    taskkill /f /im deploy.exe
    }
Function ConfigureLyncCertificates ($CAConfig, $DomainName, $NetBiosName){
    Invoke-Command -ComputerName spdev-dc.pocketdomain.corp -ScriptBlock {restart-service -ServiceName certsvc; do {start-sleep 5} until ((get-service -Name certsvc).status -eq "running")}
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
Function InstallLyncBinaries ($LyncMediaPath) {
    $window = SpawnWindow "$LyncMediaPath\Setup\amd64\Setup2.exe" "/sourcedirectory:$LyncMediaPath\Setup\amd64\"
    WaitForString $window "Installation Location"
    sendkey "%i" $window
    activate "End User License Agreement"
    start-sleep 3
    sendkey "%a"
    tab 3
    sendkey "{ENTER}"
    Activate Wizard
    taskkill /f /im deploy.exe
    }

Function InstallSQLExpress ($Instance) {
    Write-Output "Installing SQL instance: $instance"
    Start-Process -FilePath "$InstallPath\SQLEXPR_x64_ENU.EXE" -wait -argumentlist "/QUIET /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=$instance /TCPENABLED=1 /SQLSVCACCOUNT=""NT AUTHORITY\NetworkService"" /SQLSYSADMINACCOUNTS=""Builtin\Administrators"" /BROWSERSVCSTARTUPTYPE=""Automatic"" /AGTSVCACCOUNT=""NT AUTHORITY\NetworkService"" /SQLSVCSTARTUPTYPE=""Automatic"""
    }

Function InstallPreReqs {
    Write-Output "Installing NetFx3 onto DC..."
    invoke-command -ComputerName spdev-dc -ScriptBlock {dism /enable-feature /all /featurename:NetFx3 /online /limitaccess /source:D:\sources\sxs}
	Write-Output "Installing NetFx3 onto $env:computername"
    dism /enable-feature /all /featurename:NetFx3 /online /limitaccess /source:\\spdev-dc\c$\Windows\WinSxS
    Write-Output "Compiling UI automation code..."
    $path = 'C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.0'
    compile-csharp -code $csharp -references 'System.Windows.Forms.dll',"$path\UIAutomationClient.dll","$path\UIAutomationTypes.dll"
    Write-Output "Installing features..."
    Add-WindowsFeature RSAT-ADDS, Web-Server, Web-Static-Content, Web-Default-Doc, Web-Http-Errors, Web-Asp-Net, Web-Net-Ext, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-Client-Auth, Web-Filtering, Web-Stat-Compression, Web-Dyn-Compression, NET-WCF-HTTP-Activation45, Web-Asp-Net45, Web-Mgmt-Tools, Web-Scripting-Tools, Web-Mgmt-Compat, Desktop-Experience, Telnet-Client, BITS, Windows-Identity-Foundation -Source \\spdev-dc\c$\windows\winsxs
    Reg Add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel" /V "EnableSessionTicket" /D 2 /T REG_DWORD /F
    Write-Output "Installing Silverlight..."
    start-process -filepath "$InstallPath\Silverlight_x64.exe" -ArgumentList "/q /norestart" -Wait
    Write-Output "Installing VCRedist..."
    start-process -filepath "$LyncMediaPath\Setup\amd64\vcredist_x64.exe" -ArgumentList "/q /norestart" -Wait
    }


try {


    InstallPreReqs
    AddLyncShare $LyncSharePath
    InstallLyncBinaries $LyncMediaPath
    InstallTools
    import-module 'C:\Program Files\Common Files\Microsoft Lync Server 2013\Modules\Lync\Lync.psd1'
    Install-CSAdServerSchema -Confirm:$false -Verbose 
    Enable-CSAdForest  -Verbose -Confirm:$false
    Enable-CSAdDomain -Verbose -Confirm:$false 

    InstallSQLExpress "RTCLocal"
    InstallSQLExpress "LYNCLocal"
    InstallSQLExpress "RTC"

    DeployTopology $TopologyPath
    Add-ADGroupMember "CSAdministrator" -Members "Domain Admins"
    InstallServerComponents
    ConfigureLocalManagementStore
    InstallMoreServerComponents
    ConfigureLyncCertificates $CAConfig $DomainName $NetBiosName
    Start-CSWindowsService -NoWait -Verbose
    Invoke-CsManagementStoreReplication
    } catch {$error | out-file c:\error.txt; notepad c:\error.txt}
