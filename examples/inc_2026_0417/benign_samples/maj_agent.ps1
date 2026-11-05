# Téléchargement de la mise à jour de l'agent de supervision depuis le dépôt interne
$wc = New-Object Net.WebClient
$wc.DownloadFile('https://repo.corp.local/agents/monitoring-agent-2.4.msi', "$env:TEMP\monitoring-agent.msi")
Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\monitoring-agent.msi`" /qn" -Wait
Write-Host "Agent de supervision mis à jour"
