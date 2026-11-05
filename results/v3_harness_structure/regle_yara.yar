rule PowerShell_AMSI_Bypass_Persistence {
    meta:
        description = "Detects PowerShell script with AMSI bypass and persistence capabilities"
        author = "SOC Analyst N2"
        incident = "INC-2026-0417"
        reference = "C7"

    strings:
        $amsi_bypass = "amsiInitFailed"
        $reg_persistence = "Set-ItemProperty"
        $reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $task_persistence = "New-ScheduledTaskAction"
        $task_trigger = "New-ScheduledTaskTrigger"
        $hidden_window = "-WindowStyle Hidden"

    condition:
        $amsi_bypass and ($reg_persistence and $reg_path or $task_persistence) and $hidden_window
}