rule PowerShell_Malware_Facture {
    meta:
        description = "Detects the malicious PowerShell script facture_2024-11.ps1 based on AMSI bypass and keylogging signatures"
        author = "SOC Analyst"
        date = "2024-11-16"
        reference = "C8, C10"

    strings:
        $amsi_bypass = "amsiInitFailed" nocase
        $keylog_api = "GetAsyncKeyState" nocase
        $keylog_api2 = "ToUnicode" nocase
        $exfil_url = "http://192.168.1.100:8080/beacon" nocase
        $sandbox_check = "sandboxIndicators" nocase

    condition:
        any of them
}