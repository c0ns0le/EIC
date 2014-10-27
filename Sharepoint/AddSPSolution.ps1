


Add-SPSolution -LiteralPath C:\deploy\JiveForSharepoint_2013_v3.1.0.1.wsp
Install-SPSolution -Identity JiveForSharepoint_2013_v3.1.0.1.wsp -WebApplication "https://jiveintegration.pocketdomain.corp" -GACDeployment
