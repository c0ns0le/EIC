if ($PSScriptRoot) {$ScriptPath = $PSScriptRoot} else {$ScriptPath = "C:\EIC\Deploy"}

[xml]$XML = Get-Content "$ScriptPath\Settings.xml"

$OmniParameter = @{
    ADDSSettings =  	  $XML.Configuration.Hosts.ADDSSettings;
    SQLHostSettings	=	  $XML.Configuration.Hosts.SQLHostSettings;
    SP2013Settings =	  $XML.Configuration.Hosts.SP2013Settings;
    SP2010Settings =	  $XML.Configuration.Hosts.SP2010Settings;
    Lync2013StdSettings = $XML.Configuration.Hosts.Lync2013StdSettings;
    Lync2010StdSettings = $XML.Configuration.Hosts.Lync2010StdSettings;
    W8ClientSettings =    $XML.Configuration.Hosts.W8ClientSettings;
    W7ClientSettings =    $XML.Configuration.Hosts.W7ClientSettings;
    SetupPath = 	      $XML.Configuration.Paths.SetupPath;
    NetBiosName	=	      $XML.Configuration.ADSettings.NetBiosName;
    TLD	=	              $XML.Configuration.ADSettings.TLD;
    NetMask	=	          $XML.Configuration.Networking.NetMask;
    Gateway	=	          $XML.Configuration.Networking.Gateway;
    Password =  	      $XML.Configuration.ADSettings.Password;

    SQLAgentUsername =    $XML.Configuration.SQLSettings.SQLAgentUsername;
    SQLEngineUsername =   $XML.Configuration.SQLSettings.SQLEngineUsername;
    SQLExpressFilePath =  $XML.Configuration.SQLSettings.SQLExpressFilePath;
    SQLInstance =         $XML.Configuration.SQLSettings.SQLInstance

    Server2012MediaPath = $XML.Configuration.Paths.Server2012MediaPath;
    UserListFileName =    $XML.Configuration.Paths.UserListFileName;
    GroupListFileName =   $XML.Configuration.Paths.GroupListFileName;
    UserOU =	          $XML.Configuration.ADSettings.UserOU;
    GroupOU	=	          $XML.Configuration.ADSettings.GroupOU;
    SQLConfigPath = 	  $XML.Configuration.Paths.SQLConfigPath;
    AutoSPInstallerPath	= $XML.Configuration.Paths.AutoSPInstallerPath;
    CAHost =	          $XML.Configuration.Hosts.ADDSSettings.Hostname;
    DNSServer = 	      $XML.Configuration.Hosts.ADDSSettings.IPAddress;
    StepFilePath =        $XML.Configuration.Paths.StepFilePath;
    FlowFilePath =        $XML.Configuration.Paths.FlowFilePath;
    TopologyPath =        $XML.Configuration.Paths.TopologyPath;
    LyncMediaPath =       $XML.Configuration.Paths.LyncMediaPath;
    LyncSharePath =       $XML.Configuration.Paths.LyncSharePath;
    PolipoSetupPath =     $XML.Configuration.Paths.PolipoSetupPath;
    InstallPath =         $XML.Configuration.Paths.InstallPath;
    SharepointModule =    $XML.Configuration.Paths.SharepointModule;
    LicenseKey2013 =      $XML.Configuration.Hosts.SP2013Settings.LicenseKey;
    LicenseKey2010 =      $XML.Configuration.Hosts.SP2010Settings.LicenseKey;
    DomainAdmin	=	      "$($XML.Configuration.ADSettings.NetBiosName)\Administrator";
    DomainName =	      "$($XML.Configuration.ADSettings.NetBiosName).$($XML.Configuration.ADSettings.TLD)";
    CAConfig =	          "$($XML.Configuration.Hosts.ADDSSettings.Hostname).$($XML.Configuration.ADSettings.NetBiosName).$($XML.Configuration.ADSettings.TLD)\$($XML.Configuration.Hosts.ADDSSettings.Hostname)";
    DomainUserPath =	  "OU=$($XML.Configuration.ADSettings.UserOU),DC=$($XML.Configuration.ADSettings.NetBiosName),DC=$($XML.Configuration.ADSettings.TLD)";
    DomainGroupPath	=	  "OU=$($XML.Configuration.ADSettings.GroupOU),DC=$($XML.Configuration.ADSettings.NetBiosName),DC=$($XML.Configuration.ADSettings.TLD)";
    DomainUserList =	  (Get-Content "$ScriptPath\$($XML.Configuration.Paths.UserListFileName)");
    DomainGroupList	=	  (Get-Content "$ScriptPath\$($XML.Configuration.Paths.GroupListFileName)");	
    LyncUserList =        (Get-Content "$ScriptPath\$($XML.Configuration.Paths.UserListFileName)" | Select-String -Pattern "Lync");
    SharepointUserList =  (Get-Content "$ScriptPath\$($XML.Configuration.Paths.UserListFileName)" | Select-String -Pattern "Sharepoint");
    
    }

$OmniParameter | Export-Clixml "$Env:Temp\OmniParameter.xml" -Force