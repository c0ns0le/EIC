$NetworkWMI = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
$NetworkWMI.SetDNSServerSearchOrder("192.168.1.10")
