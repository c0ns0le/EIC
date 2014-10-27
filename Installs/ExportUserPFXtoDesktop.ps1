$CertToExport = dir cert:\CurrentUser\My | select -first 1
$CertType = [System.Security.Cryptography.X509Certificates.X509ContentType]::pfx
$PrivateKeyPassword = 'Abc123!'
$CertToExportInBytesForPFXFile = $CertToExport.export($CertType, $PrivateKeyPassword)
[system.IO.file]::WriteAllBytes("$env:userprofile\Desktop\$env:username.pfx", $CertToExportInBytesForPFXFile)