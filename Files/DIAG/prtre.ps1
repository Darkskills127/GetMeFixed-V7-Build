$ProfileName = Get-NetConnectionProfile
 
Set-NetConnectionProfile -Name $ProfileName.Name -NetworkCategory Private
 
Get-NetConnectionProfile
netsh advfirewall firewall set rule group="network discovery" new enable=yes
