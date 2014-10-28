
Function LoadParameters {
    if ($PSScriptRoot) {$ScriptPath = $PSScriptRoot} else {$ScriptPath = "C:\EIC\Deploy"}
    [xml]$Script:XML = Get-Content "$ScriptPath\Settings.xml" 
    $SpecialNodes = @("Hosts","DNSRecords","DerivedParameters")
    $ExclusionXPath = ""
    $SpecialNodes | % { $ExclusionXpath += "[not(self::$_)]" }
    $ConfigNodes = $XML | Select-XML -XPath "//Configuration/*$ExclusionXpath"

    $ConfigNodes | % { $_.Node.ChildNodes.Name | % { Set-Variable $_ -Value ($xml.SelectSingleNode("//$_").innertext) -Scope Script } }
    $XML.Configuration.Hosts.ChildNodes | % { Set-Variable $_.Name -Value $_ -Scope Script }
    
    $DerivedParameters = $xml | Select-XML -XPath "//Configuration/DerivedParameters" 
    $DerivedParameters | % { $_.Node.ChildNodes.Name | %{ Set-Variable $_ -Value (& ([scriptblock]::create("$($xml.SelectSingleNode(""//$_"").innertext)"))) -Scope Script -Force }}
    
    }

Function ValidateParameters {
     $RegexToCheck = "$([regex]::Escape($SetupPath))"
     $PathsToCheck = $XML.Configuration.Paths.ChildNodes | ? { $_.innertext -match $RegexToCheck -AND $_.innertext -match "\."} | %{$_.innertext}
     $MissingFiles = ""
     $PathsToCheck | % { if (-NOT (test-path $_)) {$MissingFiles += "$_`r`n"} }
     if ($MissingFiles) {write-host "Missing files:";write-host $MissingFiles; throw "Missing files!"}
    }

Function Initialize($Settings) {
    Write-Output "Initializing $($Settings.Hostname)"
    Disable-Task "\Microsoft\Windows\Server Manager\ServerManager"
    Create-LocalUser "administrator" $Password
    Add-Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' '1' 'String'
    Add-Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName' 'Administrator' 'String'
    Add-Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword' $Password 'String'
    Add-Registry 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' '0' 'DWord'
    Add-Registry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' 'EnableLUA' '0' 'DWord'
    Add-Registry 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' 'DisableFirstRunCustomize' '1' 'DWord'
    Enable-FirewallGroup "Remote Desktop"
    Enable-FirewallGroup "Remote Eventlog Management"
    Enable-FirewallGroup "Windows Remote Management"
    Enable-FirewallGroup "File and Print Sharing"
    Set-Networking $Settings.IPAddress
    Set-EnvironmentVariable "Version" $Settings.Version
    Set-EnvironmentVariable "Role" $Settings.Role
    Set-Variable Role -Value $Settings.Role -Scope Script
    Join-Domain $Settings.Hostname $Settings.Role
    #net localgroup "Remote Desktop Users" /add "$($DomainName)\Domain Users"
    }
Function Add-Registry ($Path, $Name, $Value, $PropertyType) {
    if (-NOT (Test-Path $Path)) { New-Item -path $Path -Force }
    New-ItemProperty -path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force
    }
Function New-CertificateRequest {
    param (
        [Parameter(Mandatory=$true, HelpMessage = "Please enter the subject beginning with CN=")]
        [ValidatePattern("CN=")]
        [string]$subject,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the SAN domains as a comma separated list")]
        [array]$SANs,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
        [string]$OnlineCA,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
        [string]$CATemplate = "WebServer"
    )
 
    ### Preparation
    $subjectDomain = $subject.split(',')[0].split('=')[1]
    if ($subjectDomain -match "\*.") {
        $subjectDomain = $subjectDomain -replace "\*", "star"
    }
    $CertificateINI = "$subjectDomain.ini"
    $CertificateREQ = "$subjectDomain.req"
    $CertificateRSP = "$subjectDomain.rsp"
    $CertificateCER = "$subjectDomain.cer"
 
    ### INI file generation
    new-item -type file $CertificateINI -force
    add-content $CertificateINI '[Version]'
    add-content $CertificateINI 'Signature="$Windows NT$"'
    add-content $CertificateINI ''
    add-content $CertificateINI '[NewRequest]'
    $temp = 'Subject="' + $subject + '"'
    add-content $CertificateINI $temp
    add-content $CertificateINI 'Exportable=TRUE'
    add-content $CertificateINI 'KeyLength=2048'
    add-content $CertificateINI 'KeySpec=1'
    add-content $CertificateINI 'KeyUsage=0xA0'
    add-content $CertificateINI 'MachineKeySet=True'
    add-content $CertificateINI 'ProviderName="Microsoft RSA SChannel Cryptographic Provider"'
    add-content $CertificateINI 'ProviderType=12'
    add-content $CertificateINI 'SMIME=FALSE'
    add-content $CertificateINI 'RequestType=PKCS10'
    add-content $CertificateINI '[Strings]'
    add-content $CertificateINI 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"'
    add-content $CertificateINI 'szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"'
    add-content $CertificateINI 'szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"'
    if ($SANs) {
        add-content $CertificateINI 'szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"'
        add-content $CertificateINI '[Extensions]'
        add-content $CertificateINI '2.5.29.17 = "{text}"'
 
        foreach ($SAN in $SANs) {
            $temp = '_continue_ = "dns=' + $SAN + '&"'
            add-content $CertificateINI $temp
        }
    }
 
    ### Certificate request generation
    if (test-path $CertificateREQ) {del $CertificateREQ}
    certreq -new $CertificateINI $CertificateREQ
 
    ### Online certificate request and import
    if ($OnlineCA) {
        if (test-path $CertificateCER) {del $CertificateCER}
        if (test-path $CertificateRSP) {del $CertificateRSP}
        certreq -submit -attrib "CertificateTemplate:$CATemplate" -config $OnlineCA $CertificateREQ $CertificateCER
 
        certreq -accept $CertificateCER
    }
}
Function msgbox($Text){
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.MessageBox]::Show($Text)
    }

Function Add-Task ($Stage) {
    schtasks.exe /CREATE /RU 'builtin\users' /SC ONLOGON /RL HIGHEST /TN "$Stage" /tr "powershell.exe -noexit -file $SetupPath\Setup.ps1 -Stage $Stage" /F
    }

Function Register-DNS ($Record, $IP, $Type = "A"){
    $DomainCredential = New-Object System.Management.Automation.PSCredential ($DomainAdmin, ($Password | ConvertTo-SecureString -AsPlainText -Force))
    $Command = "dnscmd /recordadd $DomainName $Record $Type $IP"
    invoke-command -ComputerName ($Env:LogonServer -replace "\\\\","") ([scriptblock]::Create("invoke-expression ""$Command""")) -Credential $DomainCredential
    }

Function RegisterDNS {
    $DNSNodes = $XML | Select-XML -XPath "//Configuration/DNSRecords"
    $DNSNodes.Node.ChildNodes | %{ 
        $DomainCredential = New-Object System.Management.Automation.PSCredential ($DomainAdmin, ($Password | ConvertTo-SecureString -AsPlainText -Force))
        $Command = "dnscmd /recordadd $DomainName $($_.Name) $($_.Type) $($_.Data)"
        invoke-command -ComputerName $ADDS.hostname ([scriptblock]::Create("invoke-expression ""$Command""")) -Credential $DomainCredential
        }
    }

Function Create-LocalUser ($Username, $Password) {
    if (-not [ADSI]::Exists("WinNT://./$username")) {
        $cn = [ADSI]"WinNT://."
        $user = $cn.Create("User","$Username")
        $user.SetPassword("$Password")
        $user.setinfo()
        $user.UserFlags.value = $user.UserFlags.value -bor 0x10000
        $user.setinfo()
        } 
    Else {
        $user = [ADSI]"WinNT://./$username"
        $user.SetPassword("$Password")
        $user.setinfo()
        $user.UserFlags.value = $user.UserFlags.value -bor 0x10000
        $user.setinfo()
        }
    }
Function Disable-Task ($TaskName) {
    Invoke-Expression "schtasks.exe /CHANGE /tn ""$TaskName"" /disable"
    }
Function Enable-FirewallGroup ($FirewallGroup) {
    Invoke-Expression "netsh advfirewall firewall set rule group=""$FirewallGroup"" new enable=yes"
    }
Function Set-Networking ($IP){
    do {write-host "Getting network adapter...";start-sleep 3}
    until ((Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'" | select -first 1))
    $NetworkWMI = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'" | select -first 1
    $NetworkWMI.EnableStatic($IP, $NetMask)
    $NetworkWMI.SetGateways($Gateway, 1)
    $NetworkWMI.SetDNSServerSearchOrder($ADDS.ipaddress)
    }
Function Set-EnvironmentVariable ($Name, $Value){
    if ($Value) {
        [System.Environment]::SetEnvironmentVariable($Name, $Value, "Machine")
        }
    }
Function Join-Domain ($ServerName, $Role){

    if ($Role -eq 'DC') {
        Rename-Computer $ServerName
        } else {
        While (!(Test-Connection $DomainName -Quiet)) {
            Read-Host "Can't reach $($DomainName). Retrying..."
            Start-Sleep 3
            } 
        if (Test-Connection $ServerName -Quiet) {$Options -= 2}
        $ComputerWMI = Get-WmiObject win32_computersystem
        $Options = 23
        $ComputerWMI.JoinDomainOrWorkGroup($DomainName, $Password, $DomainAdmin, $Null, $Options)
        $ComputerWMI.Rename($ServerName,$Password,$DomainAdmin)
        Add-Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName' $DomainAdmin 'String'
        }
    }
Function Install-NetFX3 {
    if ($Role -eq "DC"){New-SmbShare -Name winsxs -Path C:\windows\winsxs -FullAccess "Everyone"}
    if (!((Get-WindowsFeature net-framework-core).installed)){
        If ($Role -eq "DC"){
            $Source = $Server2012Media
            } ELSE {
            $Source = "\\$($ADDS.hostname)\winsxs"
            }
        While (!(Test-Path $Source)){Write-Output "NetFX3 Installation Error: Unable to reach $source.  Trying again in 5 seconds...";Start-Sleep 5}
        Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:$Source" -Wait
        } Else {
        Write-Output "NetFX3 already installed."
        }
    }
Function Create-FirewallRule ($Name, $Protocol, $Direction, $Port){
     Invoke-Expression "netsh advfirewall firewall add rule name=""$Name"" protocol=$Protocol dir=$Direction localport=$Port action=allow enable=yes"
     }

Function Install-SQLExpress ($Instance) {
    if (-not (test-path $SQLExpressFile)) {
        if (Test-Connection "http://download.microsoft.com" -Quiet) {
            wget http://download.microsoft.com/download/E/A/E/EAE6F7FC-767A-4038-A954-49B8B05D04EB/Express%2064BIT/SQLEXPR_x64_ENU.exe -OutFile $SQLExpressFile
            } 
        else {
            write-host "Can't find $SQLExpressFile and I can't reach http://download.microsoft.com."; throw "Can't find SQLExpress installer."
            }
        }
    Write-Output "Installing SQL instance: $instance"
    Start-Process -FilePath $SQLExpressFile -wait -argumentlist "/QUIET /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=$instance /TCPENABLED=1 /SQLSVCACCOUNT=""NT AUTHORITY\NetworkService"" /SQLSYSADMINACCOUNTS=""Builtin\Administrators"" /BROWSERSVCSTARTUPTYPE=""Automatic"" /AGTSVCACCOUNT=""NT AUTHORITY\NetworkService"" /SQLSVCSTARTUPTYPE=""Automatic"""
    }

Function Install-Polipo {
    Start-Process -FilePath $PolipoSetupFile -Wait
    }

Function Add-SRVRecord ($Target, $Name, $Port) {

    $Command = "Add-DnsServerResourceRecord -Srv -DomainName ""$Target.$($DomainName)"" -ZoneName ""$($DomainName)"" -Name $Name -Port $Port -Priority 0 -Weight 0"
    $DomainCredential = New-Object System.Management.Automation.PSCredential ($DomainAdmin, ($Password | ConvertTo-SecureString -AsPlainText -Force))
    $Scriptblock = [scriptblock]::Create($Command)
    Invoke-Command -ScriptBlock $Scriptblock -ComputerName ($Env:LogonServer -replace "\\\\","") -Credential $DomainCredential
    }


