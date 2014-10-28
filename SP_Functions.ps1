
Function Update-TrustedIdentityTokenIssuer($Identifier, $ADFSName, $URL){
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
    start-process -FilePath "$AutoSPInstallerFile" -argumentlist "$AutoSPInstallerXMLFile"
    throw "Installing Sharepoint, no reboot required."
    }
Function Setup-Sharepoint {
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
    New-CertificateRequest -subject "CN=$Env:Computername" -OnlineCA $CAConfig
    New-CertificateRequest -subject "CN=*.$DomainName" -OnlineCA $CAConfig
    }

Function Update-AutoSPInstallerXML{
    $Entries = get-content $AutoSPInstallerXMLFile | Select-String -Pattern "\%\w+\%" | %{$_.matches[0].groups.value} | select -Unique
    $RawXML = get-content $AutoSPInstallerXMLFile -raw
    $Version = $Env:Version
    $LicenseKey = Get-Variable -Name "LicenseKey$Version" -ValueOnly
    foreach ($Entry in $Entries) {$RawXML = $RawXML -replace $Entry,(Get-Content "Variable:\$($Entry -replace '%')")}
    [xml]$XML = $RawXML
    $xml.Save($AutoSPInstallerXMLFile)
    }


#New-SPWebApplication -Name "Curltest2" -ApplicationPool "Curltest2" -AuthenticationMethod "NTLM" -ApplicationPoolAccount (Get-SPManagedAccount "pocketdomain\sp_farm") -Port 80 -URL "https://curltest2.pocketdomain.corp" -AuthenticationProvider (New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication)
#$ap = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication 
#Get-SPWebApplication -Identity http://curltest.pocketdomaincorp | New-SPWebApplicationExtension -Name IntranetSite -HostHeader curltest2intranet -Zone Intranet -URL http://intranet.sitename.com -Port 9876 -AuthenticationProvider $ap

#chevy SUV 931BCM
