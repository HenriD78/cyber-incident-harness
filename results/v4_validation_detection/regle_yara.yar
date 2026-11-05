
rule PowerShell_AMSI_Bypass_Persistence {
    meta:
        description = "Detects PowerShell script with AMSI bypass and persistence capabilities observed in INC-2026-0417"
        author = "SOC Analyst N2"
        date = "2024-11-16"
        reference = "INC-2026-0417"
        mitre_attack = "T1685, T1547.001"

    strings:
        $amsi_bypass = "amsiInitFailed" nocase
        $amsi_ref = "AmsiUtils" nocase
        $reg_run = "CurrentVersion\\Run" nocase
        $sched_task = "New-ScheduledTaskAction" nocase
        $hidden_win = "WindowStyle Hidden" nocase

    condition:
        (all of ($amsi_bypass, $amsi_ref)) or (all of ($reg_run, $sched_task)) or (all of ($amsi_bypass, $hidden_win))
}
