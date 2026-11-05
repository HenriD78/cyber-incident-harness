# Lancement d'un script de configuration via -EncodedCommand (pratique courante des outils de déploiement)
$cmd = 'Get-Service -Name Spooler | Restart-Service'
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $encodedCommand
