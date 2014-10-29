param($stage)

Start-Transcript -Path "$env:USERPROFILE\Desktop\Transcript$(get-date -Format yyyyMMdd.hhmm).txt"
if ($PSScriptRoot) {$ScriptPath = $PSScriptRoot} else {$ScriptPath = "C:\EIC\Deploy"}

. "$ScriptPath\Functions.ps1"
. "$ScriptPath\SP_Functions.ps1"
. "$ScriptPath\Lync_Functions.ps1"
. "$ScriptPath\ADDS_Functions.ps1"

LoadParameters
if (Test-Path $StepFile) {[int]$Step = Get-Content $StepFile} else {$Step = 0}
$Step++; $Step | Out-File $StepFile -Force
ValidateParameters
$Flow = Get-Content $FlowFile
$LicenseKey2013 = $SP2013.licensekey
$LicenseKey2010 = $SP2010.licensekey

if (Test-Path $SharepointModule) {. $SharepointModule}


if ($stage) {$flow = $stage}

$CompletionBlock = {
    Disable-Task "EIC"; throw "Done"
    }

$ADDSFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $ADDS; Install-NetFX3 "DC"}
            2 {Install-ADDSRSATFeatures; Install-Polipo}
            3 {Install-ADDSFeatures}
            4 {Install-Forest}
            5 {Create-ADObjects; RegisterDNS; Install-PKI}
            6 {Install-ADFS3}
            7 {&$CompletionBlock}
        }
    }

$SP2013Flow = {
    switch ($step)
        {
            1 {Initialize -Settings $SP2013}
            2 {Install-NetFX3 "SP"; Setup-Sharepoint}
            3 {Install-SQLExpress "Sharepoint"; Install-Sharepoint}
            4 {&$CompletionBlock}
        }
    }


$Lync2013StdFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $Lync2013Std}
            2 {Install-NetFX3 "Lync"; InstallWasp;}# DeployLync2013Std}
            3 {}#DeployLyncRoundTwo}
            3 {}#InstallLyncUpdates}
            4 {}#ConfigureLyncUpdates}
            5 {}#&$CompletionBlock}
        }
    }

$W7ClientFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $W7Client}
            #2 {Install-Chocolatey}
            2 {&$CompletionBlock}
        }
    }



switch ($Flow)
    {
        "adds"        {&$ADDSFlow}
        "sql"         {&$SQLFlow}
        "sqlsp2013"   {&$SP2013SQLFlow}
        "sp2013"      {&$SP2013Flow}
        "sp2013post"  {Finalize-SP2013}
        "Lync2013Std" {&$Lync2013StdFlow}
        "Lync2010Std" {&$Lync2010StdFlow}
        "W7Client"    {&$W7ClientFlow}
        "W8Client"    {&$W7ClientFlow}
    }

ipconfig /all

if (!($Error[0])) {Restart-Computer} else {Write-Host "Errors!"; $Error | Select-Object * | Out-File c:\errors.txt -Append; notepad.exe c:\errors.txt}
