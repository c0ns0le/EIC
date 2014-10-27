# This commands script file creates a new BITS transfer job that downloads all Sharepoint 2013 Prerequisites files for Windows Server 2012
# Author: Muawiyah Shannak (@MuShannak)
# Blog: http://mushannak.blogspot.com/
# Last Update : 9/28/2013
# Source: http://gallery.technet.microsoft.com/Script-to-SharePoint-2013-702e07df

$DestinationFolder = Read-Host -Prompt "Please enter the destination path for Sharepoint 2013 Prerequisites files"

# Note: The Prerequisite Files URLs are subject to change at Microsoft's discretion - check http://technet.microsoft.com/en-us/library/cc262485(v=office.15).aspx and update the links.
$FilesUrlList = ( 
		"http://download.microsoft.com/download/9/1/3/9138773A-505D-43E2-AC08-9A77E1E0490B/1033/x64/sqlncli.msi", # SQL Server 2008 R2 SP1 Native Client
		"http://download.microsoft.com/download/8/F/9/8F93DBBD-896B-4760-AC81-646F61363A6D/WcfDataServices.exe", # Microsoft WCF Data Services 5.0
		"http://download.microsoft.com/download/9/1/D/91DA8796-BE1D-46AF-8489-663AB7811517/setup_msipc_x64.msi", # Microsoft Information Protection and Control Client (MSIPC)
		"http://download.microsoft.com/download/E/0/0/E0060D8F-2354-4871-9596-DC78538799CC/Synchronization.msi", # Microsoft Sync Framework Runtime v1.0 SP1 (x64) 
		"http://download.microsoft.com/download/0/1/D/01D06854-CA0C-46F1-ADBA-EBF86010DCC6/r2/MicrosoftIdentityExtensions-64.msi", # Windows Identity Extensions
		"http://download.microsoft.com/download/D/7/2/D72FD747-69B6-40B7-875B-C2B40A6B2BDD/Windows6.1-KB974405-x64.msu", # Windows Identity Foundation (KB974405)
		"http://download.microsoft.com/download/A/6/7/A678AB47-496B-4907-B3D4-0A2D280A13C0/WindowsServerAppFabricSetup_x64.exe", #Windows Server AppFabric
		"http://download.microsoft.com/download/7/B/5/7B51D8D1-20FD-4BF0-87C7-4714F5A1C313/AppFabric1.1-RTM-KB2671763-x64-ENU.exe" # CU 1 for AppFabric 1.1 (KB2671763)
             )

function CreateDestinationFolder()
{
	Try
	{
		## Return true if the Destination Folder exists, otherwise return false
		If (!(Test-Path "$DestinationFolder" -pathType container))
		{
			##Creates the destination folder if it does not exist
			New-Item $DestinationFolder -ItemType Directory
		}
	}
	Catch
	{
		Write-Host "An error occurred creating destination folder (`'$DestinationFolder`'), Please check the path,and try again."
		Pause
		break
	}
}

function DownloadSP2013Files()
{
	Import-Module BitsTransfer
	Write-Host "BitsTransfer Module is loaded"
	Write-Host "Downloading..."

	ForEach ($FileUrl in $FilesUrlList)
	{
		## Get the file name
		$DestinationFileName = $FileUrl.Split('/')[-1]
	
		Try
		{
			
			## Return true if the file exists, otherwise return false
			If (!(Test-Path "$DestinationFolder\$DestinationFileName"))
			{
				Write-Host "`'$FileUrl`' ..."
				Start-BitsTransfer -Source $FileUrl -Destination $DestinationFolder\$DestinationFileName -Priority High -ErrorVariable err
				If ($err) {Throw ""}
			}
			Else
			{
				Write-Host "File $DestinationFileName already exists, skipping..."
			}
		}
		Catch
		{
			Write-Warning "An error occurred downloading `'$DestinationFileName`'"
			break
		}
	}
}

function Pause($Message="Press any key to continue...")
{
	Write-Host -NoNewLine $Message
	$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	Write-Host ""
}

CreateDestinationFolder 
DownloadSP2013Files
Pause
