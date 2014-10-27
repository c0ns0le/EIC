param($stage)

if ($PSScriptRoot) {$ScriptPath = $PSScriptRoot} else {$ScriptPath = "C:\Deploy"}

start-process -filepath "powershell.exe" -argumentlist "-file ""$ScriptPath\OmniParameterGenerator.ps1""" -wait
$OmniParam = Import-Clixml "$Env:Temp\OmniParameter.xml"

. "$ScriptPath\Functions.ps1"
. "$ScriptPath\SP_Functions.ps1"
. "$ScriptPath\Lync_Functions.ps1"
. "$ScriptPath\ADDS_Functions.ps1"

if (Test-Path $OmniParam.SharepointModule) {. $OmniParam.SharepointModule}
if (Test-Path $OmniParam.FlowFilePath) {$Flow = Get-Content $OmniParam.FlowFilePath} else {Throw "No flow file present.";exit}
if (Test-Path $OmniParam.StepFilePath) {[int]$Step = Get-Content $OmniParam.StepFilePath} else {$Step = 0}

$Step++; $Step | Out-File $OmniParam.StepFilePath -Force
if ($stage) {$flow = $stage}

$CompletionBlock = {
    Disable-Task "EIC"; throw "Done"
    }

$ADDSFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $OmniParam.ADDSSettings}
            2 {Install-ADDSRSATFeatures; Install-Polipo}
            3 {Install-ADDSFeatures}
            4 {Install-Forest}
            5 {Create-ADObjects; Install-PKI}
            6 {Install-ADFS3}
            7 {&$CompletionBlock}
        }
    }

$SP2013Flow = {
    switch ($step)
        {
            1 {Initialize -Settings $OmniParam.SP2013Settings}
            2 {Setup-Sharepoint}
            3 {Install-SQLExpress "Sharepoint"; Install-Sharepoint}
            4 {&$CompletionBlock}
        }
    }

$SQLFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $OmniParam.SQLHostSettings}
            2 {Install-SQL @OmniParam}
            3 {&$CompletionBlock}
        }
    }

$Lync2013StdFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $OmniParam.Lync2013StdSettings}
            2 {Install-NetFX3 "Lync"; InstallWasp;}# DeployLync2013Std @OmniParam}
            3 {}#DeployLyncRoundTwo @OmniParam}
            3 {}#InstallLyncUpdates @OmniParam}
            4 {}#ConfigureLyncUpdates}
            5 {}#&$CompletionBlock}
        }
    }

$W7ClientFlow = {
    switch ($step)
        {
            1 {Initialize -Settings $OmniParam.W7ClientSettings}
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
        "sql"         {&$SQLFlow}
        "sp2013post"  {Finalize-SP2013}
        "Lync2013Std" {&$Lync2013StdFlow}
        "Lync2010Std" {&$Lync2010StdFlow}
        "W7Client"    {&$W7ClientFlow}
        "W8Client"    {&$W7ClientFlow}
    }

if (!($Error[0])) {Restart-Computer} else {Write-Host "Errors!"; $Error | Select-Object * | Out-File c:\errors.txt -Append; notepad.exe c:\errors.txt}
