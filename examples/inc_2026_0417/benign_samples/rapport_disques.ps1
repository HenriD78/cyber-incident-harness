# Rapport d'espace disque envoyé à l'API de supervision
$disques = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, FreeSpace, Size
$json = $disques | ConvertTo-Json
Invoke-RestMethod -Uri 'https://supervision.corp.local/api/disques' -Method Post -Body $json -ContentType 'application/json'
