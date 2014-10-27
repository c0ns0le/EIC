Function Add-ADFS3-RPTrust ($Identifier, $Name) {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $DomainName = $OmniParam.DomainName
    Import-Module ADFS
    While (!((get-service adfssrv).Status -match "Running")) {Start-Sleep 10} 
    $TransformRules = @"
@RuleTemplate = "LdapClaims"
@RuleName = "LDAP"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"), query = ";mail,userPrincipalName,tokenGroups;{0}", param = c.Value);
"@

    $AuthRules = @"
@RuleTemplate = "AllowAllAuthzRule"
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
"@
    $AddADFSRelyingPartyTrustArguments = @{
        Name = $Name
        Identifier = "urn:sharepoint:$Identifier"
        WSFedEndpoint = "https://$Identifier.$DomainName/_trust/" 
        IssuanceAuthorizationRules = $AuthRules 
        IssuanceTransformRules = $TransformRules
        }

    Add-AdfsRelyingPartyTrust @AddADFSRelyingPartyTrustArguments
    }
Function Install-Forest {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    Import-Module ADDSDeployment 
    Add-Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName' $OmniParam.DomainAdmin 'String'
    Write-Output "Installing Forest..."
    $ForestSettings = @{
        CreateDNSDelegation = $False
        DatabasePath = "C:\Windows\NTDS"
        DomainMode = "Win2012" 
        ForestMode = "Win2012"
        DomainName = $OmniParam.DomainName
        DomainNetbiosName = $OmniParam.NetBiosName
        InstallDns = $True
        LogPath = "C:\Windows\NTDS"
        NoRebootOnCompletion = $True
        SysvolPath = "C:\Windows\SYSVOL"
        Force = $True
        SafeModeAdministratorPassword = ($OmniParam.Password | ConvertTo-SecureString -AsPlainText -Force)
        }
    Install-ADDSForest @ForestSettings
    }


Function Install-PKI {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $NetBiosName = $OmniParam.NetBiosName
    $TLD = $OmniParam.TLD
    Import-Module ServerManager
    Write-Output "Adding Certificate Services..."
    Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools 
    Add-WindowsFeature ADCS-Enroll-Web-Svc,Adcs-Enroll-Web-Pol,ADCS-Web-Enrollment
    $PKISettings = @{
        CACommonName = "$env:COMPUTERNAME"
        CAType = "EnterpriseRootCA" 
        CryptoProviderName = "RSA#Microsoft Software Key Storage Provider" 
        KeyLength = 2048 
        HashAlgorithmName = "SHA1"
        ValidityPeriod = "Years"
        ValidityPeriodUnits = 3 
        Force = $True
        }
    Install-AdcsCertificationAuthority @PKISettings
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$NetBiosName,DC=$TLD" /G """NT Authority\Authenticated Users"":CA;enroll"
    Install-AdcsWebEnrollment  -Confirm:$False
    #Install-AdcsEnrollmentWebService -CAConfig $CAConfig -SSLCertThumbprint $WildCard.Thumbprint -AuthenticationType Username -Confirm:$False -Force
    #Install-AdcsEnrollmentPolicyWebService -SSLCertThumbprint $WildCard.Thumbprint -AuthenticationType UserName -Confirm:$false -Force
    }
Function Install-ADFS3 {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $NetBiosName = $OmniParam.NetBiosName
    $TLD = $OmniParam.TLD
    $DomainName = $OmniParam.DomainName
    $Password = $OmniParam.Password
    $CAConfig = $OmniParam.CAConfig

    Add-WindowsFeature ADFS-Federation -IncludeManagementTools -IncludeAllSubFeature
    Import-Module ADFS
    if (!(Get-ChildItem Cert:\LocalMachine\My | ?{ $_.Subject -eq "CN=adfs3.$DomainName"})) {New-CertificateRequest -subject "CN=adfs3.$DomainName" -OnlineCA $CAConfig}
    $ADFS3Certificate = Get-ChildItem Cert:\LocalMachine\My | ? Subject -eq "CN=adfs3.$DomainName"
    $ADFS3Credential = New-Object System.Management.Automation.PSCredential ("$NetBiosName\ADFS_SVC", ($Password | ConvertTo-SecureString -AsPlainText -Force))
    $ADFSSettings = @{
        CertificateThumbprint = $ADFS3Certificate.Thumbprint
        FederationServiceDisplayName = "$DomainName ADFS Login"
        FederationServiceName = "adfs3.$DomainName"
        ServiceAccountCredential = $ADFS3Credential
        }
    Install-ADFSFarm @ADFSSettings
    While (!((get-service adfssrv).Status -match "Running")) {Start-Sleep 10} 

    $ADFSIPAddress = (Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'").ipaddress[0]
    $certRefs=Get-AdfsCertificate -CertificateType Token-Signing
    [System.IO.File]::WriteAllBytes("c:\ADFS3TokenSigningCert.cer", ($certRefs[0].Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))
    Register-DNS "adfs3" $ADFSIPAddress
    Add-ADFS3-RPTrust "portal" "Sharepoint Portal"
    Add-ADFS3-RPTrust "mysites" "Sharepoint Mysites"
    Set-ADFSProperties –ExtendedProtectionTokenCheck None
    Set-ADFSProperties -WIASupportedUserAgents @(“MSIE 6.0", “MSIE 7.0", “MSIE 8.0", “MSIE 9.0",“MSIE 10.0", “Trident/7.0", “MSIPC”, “Windows Rights Management Client”, "Mozilla/5.0")
    Restart-Service ADFSSrv

    }
Function Install-ADDSFeatures {
    Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools; 
    Add-WindowsFeature -Name "DNS" -IncludeAllSubFeature -IncludeManagementTools; 
    Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools
    New-SmbShare -Name winsxs -Path C:\windows\winsxs -FullAccess "Everyone"
    }
Function Install-ADDSRSATFeatures {
    Add-WindowsFeature RSAT-AD-Tools,RSAT-DNS-Server
    }
Function Create-ADObjects {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    Create-ADUsers; 
    Create-ADGroups @OmniParam; 
    Set-ADUser -Identity "Administrator" -EmailAddress "admin@$($OmniParam.DomainName)"
    }

Function Create-ADUsers ($DomainUserList, $DomainUserPath){
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $UserOU = (($OmniParam.DomainUserPath -split ",")[0] -replace "OU=","")
    if (-NOT ([adsi]::Exists("LDAP://$($OmniParam.DomainUserPath)"))){New-ADOrganizationalUnit -Name $UserOU}
    Foreach ($User in $OmniParam.DomainUserList) {
        $NewUserParameters = @{
            Name=$User;
            GivenName=$User;
            Surname="Jones"
            Path=$OmniParam.DomainUserPath;
            Enabled=$True;
            AccountPassword=($Omniparam.Password | ConvertTo-SecureString -AsPlainText -Force);
            EmailAddress="$User@$($Omniparam.DomainName)"
            UserPrincipalName="$User@$($Omniparam.DomainName)"
            PasswordNeverExpires=$True
            }
        New-ADUser @NewUserParameters 
        }
    }
Function Create-ADGroups ($DomainGroupList, $DomainGroupPath) {
    $OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"
    $GroupOU = (($OmniParam.DomainGroupPath -split ",")[0] -replace "OU=","")
    if (-NOT ([adsi]::Exists("LDAP://$($OmniParam.DomainGroupPath)"))){New-ADOrganizationalUnit -Name $GroupOU}
    Foreach ($Group in $OmniParam.DomainGroupList) {
        $GroupParameters = @{
            Name=$Group;
            Path=$OmniParam.DomainGroupPath;
            GroupScope="Global"
            }
        New-ADGroup @GroupParameters; 
        Add-ADGroupMember $Group -Members "Domain Users"
        }
    }