rule Malware_PowerShell_AMSI_Bypass {
    meta:
        description = "Detects PowerShell script with AMSI bypass and specific persistence mechanisms"
        author = "SOC Analyst"
        date = "2024-11-16"
    strings:
        $amsi_bypass = "amsiInitFailed" nocase
        $reg_persistence = "CurrentVersion\\Run" nocase
        $task_persistence = "New-ScheduledTaskAction" nocase
        $keylog_api = "user32.dll" nocase
    condition:
        2 of them
}