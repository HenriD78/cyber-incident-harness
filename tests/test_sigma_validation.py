"""Régressions de l'évaluateur Sigma, sur événements synthétiques uniquement."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cyber_harness.detection.sigma as sigma_engine
import cyber_harness.tools as tools


def rule(detection):
    return (
        "title: Synthetic Sigma regression\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n"
        + detection
    )


class SigmaValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.incident, self.output = root / "incident", root / "output"
        self.incident.mkdir()
        self.output.mkdir()
        events = [
            {
                "event": "process_create",
                "image": r"C:\Windows\powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass",
                "user": "analyst",
            },
            {
                "event": "process_create",
                "image": r"C:\Windows\cmd.exe",
                "command_line": "cmd.exe /c echo benign",
                "user": "other",
            },
        ]
        (self.incident / "edr_events.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events),
            encoding="utf-8",
        )
        corpus = {
            "sigma": {
                "positifs": [{"fichier": "edr_events.jsonl", "ligne": 1}],
                "negatifs": [{"event": "process_create", "image": "other.exe"}],
            }
        }
        corpus_patch = patch.object(tools, "load_corpus", return_value=corpus)
        corpus_patch.start()
        self.addCleanup(corpus_patch.stop)
        replacement = patch.multiple(tools, INCIDENT=self.incident, OUTPUT=self.output)
        replacement.start()
        self.addCleanup(replacement.stop)

    def validate(self, detection):
        return json.loads(
            tools.validate_sigma.invoke(
                {"rule_yaml": rule(detection), "filename": "regle_sigma.yml"}
            )
        )

    def test_keyword_without_field_matches_inside_event_values(self):
        result = self.validate("  keywords:\n    - PowerShell.EXE\n  condition: keywords\n")
        self.assertTrue(result["valide"])
        self.assertTrue(result["test_concluant"])
        self.assertTrue(result["test_reussi"])
        self.assertEqual(result["detections_sur_edr"], ["edr_events.jsonl:1 (process_create)"])

    def test_keyword_list_uses_or_and_wildcards(self):
        result = self.validate(
            "  keywords:\n    - '*powershell.exe*'\n    - '*cmd.exe*'\n  condition: keywords\n"
        )
        self.assertEqual(len(result["detections_sur_edr"]), 2)

    def test_field_match_stays_exact_and_does_not_search_other_fields(self):
        result = self.validate("  selection:\n    Image: powershell.exe\n  condition: selection\n")
        self.assertEqual(result["detections_sur_edr"], [])

    def test_keyword_combines_with_field_filter_and_negation(self):
        result = self.validate(
            "  keywords:\n    - '*exe*'\n  selection:\n    User: analyst\n"
            "  filter:\n    CommandLine|contains: benign\n"
            "  condition: keywords and selection and not filter\n"
        )
        self.assertEqual(result["detections_sur_edr"], ["edr_events.jsonl:1 (process_create)"])

    def test_nonmatching_keyword_is_reported_without_crashing(self):
        result = self.validate("  keywords:\n    - nonexistent-keyword\n  condition: keywords\n")
        self.assertEqual(result["detections_sur_edr"], [])
        self.assertIn("AUCUN", result["test"])
        self.assertTrue(result["test_concluant"])
        self.assertFalse(result["test_reussi"])

    def test_evaluation_failure_is_explicitly_inconclusive(self):
        with patch.object(
            sigma_engine, "_eval", side_effect=AttributeError("synthetic unsupported expression")
        ):
            result = self.validate("  keywords:\n    - '*exe*'\n  condition: keywords\n")
        self.assertTrue(result["valide"])
        self.assertFalse(result["test_concluant"])
        self.assertFalse(result["test_reussi"])
        self.assertIn("non concluant", result["test"])
        self.assertIn("AttributeError", result["test"])

    def test_partial_hits_are_discarded_if_evaluation_fails_later(self):
        with patch.object(
            sigma_engine, "_eval", side_effect=[True, AttributeError("unsupported later event")]
        ):
            result = self.validate("  keywords:\n    - '*exe*'\n  condition: keywords\n")
        self.assertFalse(result["test_concluant"])
        self.assertFalse(result["test_reussi"])
        self.assertEqual(result["detections_sur_edr"], [])


if __name__ == "__main__":
    unittest.main()
