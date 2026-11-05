# Inventaire matériel du parc - service informatique
$os = Get-WmiObject Win32_OperatingSystem
$bios = Get-WmiObject Win32_BIOS
$av = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct
[PSCustomObject]@{
    Poste = $env:COMPUTERNAME
    OS = $os.Caption
    BIOS = $bios.Manufacturer
    Antivirus = $av.displayName
} | Export-Csv -Path "\\srv-fichiers\inventaire\$env:COMPUTERNAME.csv" -NoTypeInformation
