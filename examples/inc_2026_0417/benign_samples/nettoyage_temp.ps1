# Nettoyage des fichiers temporaires de plus de 30 jours
$limite = (Get-Date).AddDays(-30)
Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $limite } |
    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Write-Host "Nettoyage terminé"
