# Crée la tâche de sauvegarde nocturne des documents comptables
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\sauvegarde.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "SauvegardeCompta" -Action $action -Trigger $trigger -User "CORP\svc_backup"
Write-Host "Tâche de sauvegarde enregistrée"
