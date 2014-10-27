
Function Update-TrustedIdentityTokenIssuer($Identifier, $ADFSName, $URL){
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $DomainName = $OmniParam.DomainName
    $NetBiosName = $OmniParam.NetBiosName
    $TokenSigningCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$env:LOGONSERVER\c$\$($ADFSName)tokensigningcert.cer")
    If ((Get-SPTrustedRootAuthority).certificate.thumbprint -notcontains $TokenSigningCert.Thumbprint) {New-SPTrustedRootAuthority -Name "Token Signing Cert" -Certificate $TokenSigningCert}
    $emailClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" -IncomingClaimTypeDisplayName "EmailAddress" -SameAsIncoming
    $upnClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" -IncomingClaimTypeDisplayName "UPN" -SameAsIncoming
    $roleClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" -IncomingClaimTypeDisplayName "Role" -SameAsIncoming
    $sidClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid" -IncomingClaimTypeDisplayName "SID" -SameAsIncoming
    $NewSPTrustedIdentityTokenIssuerArguments = @{
        Name = "$ADFSName.$DomainName"
        Description = "$ADFSName.$DomainName"
        Realm = "urn:sharepoint:$NetBiosName"
        ImportTrustCertificate = $TokenSigningCert 
        ClaimsMappings = $emailClaimMap,$upnClaimMap,$roleClaimMap,$sidClaimMap
        SignInUrl = "https://$ADFSName.$DomainName/adfs/ls"
        IdentifierClaim = $emailClaimMap.InputClaimType
        }
    If ((Get-SPTrustedIdentityTokenIssuer).name -notcontains $NewSPTrustedIdentityTokenIssuerArguments.Name) {
        New-SPTrustedIdentityTokenIssuer @NewSPTrustedIdentityTokenIssuerArguments
        }
    $AP = Get-SPTrustedIdentityTokenIssuer | ? { $_.name -match $NewSPTrustedIdentityTokenIssuerArguments.Name }
    $AP.ProviderRealms.Add($URL, "urn:sharepoint:$Identifier")
    $AP.Update()
    $AP = $null
    }
Function Finalize-SP2013 {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $DomainName = $OmniParam.DomainName
    Start-Website "Sharepoint Central Administration v4"
    Update-TrustedIdentityTokenIssuer "portal" "adfs3" "https://portal.$DomainName" 
    Update-TrustedIdentityTokenIssuer "mysites" "adfs3" "https://mysites.$DomainName"
    Add-SPWebAppGroupClaim "https://portal.$DomainName" "GroupClaim" "adfs3.$DomainName"
    Throw "No reboot needed."
    }
Function Add-SPWebAppGroupClaim ($WebAppUrl, $GroupName, $ADFS_STS) {
    $GroupClaim = "c:0-.t|$ADFS_STS|$GroupName"
    $DisplayName = $GroupName
    $WebApp = Get-SPWebApplication $WebAppURL
    $policy = $WebApp.Policies.Add($GroupClaim, $DisplayName)
    $policyRole = $WebApp.PolicyRoles.GetSpecialRole([Microsoft.SharePoint.Administration.SPPolicyRoleType]::FullControl)
    $policy.PolicyRoleBindings.Add($policyRole)
    $WebApp.Update()
    $WebApp = $null
    $WebApp = Get-SPWebApplication $WebAppURL
    $winAp = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication
    $stsAp = Get-SPTrustedIdentityTokenIssuer $ADFS_STS
    Set-SPWebApplication -Identity $WebApp -AuthenticationProvider $stsAp, $winAp -Zone "Default"
    $WebApp.Update()
    $WebApp = $nul
    }
Function Install-Sharepoint {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    start-process -FilePath "$($OmniParam.AutoSPInstallerPath)\AutoSPInstallerLaunch.bat" -argumentlist "$($OmniParam.SetupPath)\AutoSPInstallerSettings.xml" -wait
    throw "Installing Sharepoint, no reboot required."
    }
Function Setup-Sharepoint {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    Update-AutoSPInstallerXML
    Import-Module ServerManager
    Install-WindowsFeature "RSAT-AD-Tools"
    Install-NetFX3
    Install-WindowsFeature Net-Framework-Features,Web-Server,Web-WebServer,Web-Common-Http
    Install-WindowsFeature Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors
    Install-WindowsFeature Web-App-Dev,Web-Asp-Net,Web-Net-Ext,Web-ISAPI-Ext,Web-ISAPI-Filter
    Install-WindowsFeature Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor
    Install-WindowsFeature Web-Http-Tracing,Web-Security,Web-Basic-Auth,Web-Windows-Auth,Web-Filtering
    Install-WindowsFeature Web-Digest-Auth,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression
    Install-WindowsFeature Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase
    Install-WindowsFeature Application-Server,AS-Web-Support,AS-TCP-Port-Sharing,AS-WAS-Support
    Install-WindowsFeature AS-HTTP-Activation,AS-TCP-Activation,AS-Named-Pipes,AS-Net-Framework
    Install-WindowsFeature WAS,WAS-Process-Model,WAS-NET-Environment,WAS-Config-APIs,Web-Lgcy-Scripting
    Install-WindowsFeature Windows-Identity-Foundation,Server-Media-Foundation,Xps-Viewer
    New-CertificateRequest -subject "CN=$Env:Computername" -OnlineCA $OmniParam.CAConfig
    New-CertificateRequest -subject "CN=*.$($OmniParam.DomainName)" -OnlineCA $OmniParam.CAConfig
    }

Function Update-AutoSPInstallerXML{
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $RawXML = get-content "$($OmniParam.SetupPath)\AutoSPInstallerSettings.xml" -raw
    $RawXML = $RawXML -replace "%DOMAINNAME%",$OmniParam.DomainName
    $RawXML = $RawXML -replace "%NETBIOS%",$OmniParam.NetBiosName
    $RawXML = $RawXML -replace "%PASSWORD%",$OmniParam.Password
    $RawXML = $RawXML -replace "%SQLINSTANCE%",$OmniParam.SQLInstance
    $RawXML = $RawXML -replace "%LICENSEKEY%",$OmniParam.("LicenseKey$Env:Version")
    $RawXML = $RawXML -replace "%VERSION%",$Env:Version
    [xml]$XML = $RawXML
    $xml.Save("$($OmniParam.SetupPath)\AutoSPInstallerSettings.xml")
    }
