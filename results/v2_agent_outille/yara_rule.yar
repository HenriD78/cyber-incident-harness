rule malicious_powershell_script : badware {
    strings:
        $encoded_cmd = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA"
        $ip_192_168_1_100 = "192.168.1.100"
        $temp_svchost = /\\svchost_update\.ps1/
        $run_key = /HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/
    condition:
        any of ($encoded_cmd, $ip_192_168_1_100, $temp_svchost, $run_key)
}