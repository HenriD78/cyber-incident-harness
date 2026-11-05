import base64
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cyber_harness.evidence import contains_indicator, decode_static, read_bytes
from cyber_harness.mitre import INDEX, PREFIX, refresh_reference
from cyber_harness.models import IOC, Mapping, Proposal, Protocol, Reference
from cyber_harness.runtime.control import ExecutionMonitor
from cyber_harness.tools import evaluate_sigma, evaluate_yara
from cyber_harness.workflow import build_agent, run_workflow
from tests.harness_fixtures import (
    SIGMA,
    YARA,
    AIMessage,
    FakeModel,
    call,
    factory,
    prepare_analysis,
    proposal_data,
    protocol_data,
    session_fixture,
)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)

    def run_flow(self, accepted=True, model_factory=factory, budget=100):
        phases = []

        def create(stage, s):
            phases.append(stage)
            return model_factory(stage, s)

        with redirect_stdout(io.StringIO()):
            code = run_workflow(
                self.s,
                model_factory=create,
                decide=lambda p: (accepted, "test"),
                monitor=ExecutionMonitor(budget, progress=lambda *a, **k: None),
            )
        return code, phases

    def test_acceptance_protocol_report_and_audit(self):
        code, phases = self.run_flow()
        self.assertEqual(code, 0, self.s.validate())
        self.assertEqual(
            phases, ["preuves", "ioc", "mitre", "regles", "confinement", "protocole", "rapport"]
        )
        self.assertTrue(self.s.audit.valid())
        self.assertTrue(self.s.evidence.intact())
        self.assertIsNotNone(self.s.protocol)
        self.assertIn("Aucune action exécutée", (self.s.output / "rapport_incident.md").read_text())
        log = [
            json.loads(line_text)
            for line_text in (self.s.output / "audit.jsonl").read_text().splitlines()
        ]
        self.assertTrue(any(e["type"] == "decision_humaine" for e in log))
        self.assertTrue(any(e["type"] == "outil_sortie" and e["parent_run_id"] for e in log))

    def test_refusal_report_without_protocol_or_reproposal(self):
        code, phases = self.run_flow(False)
        self.assertEqual(code, 0, self.s.validate())
        self.assertNotIn("protocole", phases)
        self.assertIsNone(self.s.protocol)
        self.assertFalse((self.s.output / "protocole_confinement.md").exists())
        self.assertEqual(self.s.decision["decision"], "refusee")
        self.assertIn("Proposition refusée", (self.s.output / "rapport_incident.md").read_text())
        with self.assertRaises(ValueError):
            self.s.decide(True)

    def test_missing_deliverables_cannot_succeed(self):
        code, _ = self.run_flow(
            model_factory=lambda stage, s: FakeModel(messages=iter([AIMessage(content="FIN")]))
        )
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLET", (self.s.output / "rapport_incident.md").read_text())

    def test_budget_reserves_report_and_keeps_total_count(self):
        code, phases = self.run_flow(budget=5)
        self.assertEqual(code, 1)
        self.assertNotIn("rapport", phases)
        self.assertEqual(self.s.phase_status["rapport"]["statut"], "secours")
        diagnostic = json.loads((self.s.output / "diagnostic_execution.json").read_text())
        self.assertLessEqual(diagnostic["appels_llm"], 5)
        self.assertTrue((self.s.output / "rapport_incident.md").exists())

    def test_no_approval_on_eof(self):
        with redirect_stdout(io.StringIO()):
            code = run_workflow(
                self.s,
                model_factory=factory,
                decide=lambda p: (_ for _ in ()).throw(EOFError()),
                monitor=ExecutionMonitor(100, progress=lambda *a, **k: None),
            )
        self.assertEqual(code, 130)
        self.assertIsNone(self.s.decision)
        self.assertIsNone(self.s.protocol)

    def test_incomplete_read_prevents_analysis(self):
        from cyber_harness.models import Analysis
        from tests.harness_fixtures import analysis_data

        self.s.enter("preuves")
        with self.assertRaisesRegex(ValueError, "toutes les pages"):
            self.s.save_analysis(Analysis.model_validate(analysis_data(self.s)))

    def test_out_of_bounds_or_wrong_hash_reference(self):
        with self.assertRaises(ValueError):
            self.s.evidence.reference("edr_events.jsonl", 0)
        ref = self.s.evidence.reference("edr_events.jsonl", 2)
        ref["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.s.evidence.validate(ref)

    def test_ioc_boundaries(self):
        self.assertFalse(contains_indicator("203.0.113.4", "203.0.113.42"))
        self.assertFalse(contains_indicator("evil.example", "notevil.example"))
        self.assertFalse(contains_indicator("http://evil/a", "http://evil/abc"))
        self.assertTrue(contains_indicator("203.0.113.42", "from 203.0.113.42"))
        self.assertEqual(self.s.verify("203.0.113.4")["references"], [])
        self.assertTrue(
            contains_indicator("malicious-domain.ru", "http://malicious-domain.ru/payload")
        )
        self.assertTrue(contains_indicator("192.168.1.100", "http://192.168.1.100:8080/"))
        self.assertTrue(contains_indicator("script.ps1", r"C:\Temp\script.ps1"))

    def test_multiline_utf16(self):
        text = "Write-Output test\nWrite-Output fin\r\n"
        self.assertEqual(
            decode_static(base64.b64encode(text.encode("utf-16-le")).decode())["texte_decode"], text
        )

    def test_derived_ioc_requires_exact_source(self):
        prepare_analysis(self.s)
        self.s.enter("ioc")
        name = "facture_2024-11.ps1.txt"
        import re

        line, encoded = next(
            (n, m.group())
            for n, line_text in enumerate(self.s.evidence.content[name], 1)
            if (m := re.search(r"[A-Za-z0-9+/]{100,}={0,2}", line_text))
        )
        result = self.s.decode(name, line, encoded)
        url = result["urls"][0]
        ioc = IOC(
            type="url",
            valeur=url,
            references=[Reference(**result["source"])],
            contexte="URL encodée",
            confiance="moyenne",
            constat_ids=["C1"],
            derivation_id=result["id"],
        )
        self.s.save_iocs([ioc])
        with self.assertRaises(ValueError):
            self.s.decode(name, 1, encoded)
        with self.assertRaises(ValueError):
            self.s.save_iocs([ioc.model_copy(update={"valeur": "http://absent.invalid"})])

    def test_phase_and_revoked_technique_checks(self):
        prepare_analysis(self.s)
        self.s.enter("mitre")
        self.s.check_mitre("T1562.001")
        with self.assertRaisesRegex(ValueError, "révoquée"):
            self.s.save_mappings(
                [Mapping(id="T1562.001", constat_ids=["C1"], justification="test")]
            )
        with self.assertRaises(ValueError):
            self.s.enter("ioc")
        with self.assertRaises(ValueError):
            self.s.save_iocs([])

    def test_protocol_rejects_changed_scope_or_unapproved_hash(self):
        prepare_analysis(self.s)
        self.s.enter("confinement")
        self.s.propose(Proposal.model_validate(proposal_data(self.s)))
        self.s.decide(True)
        self.s.enter("protocole")
        data = protocol_data(self.s)
        data["actions"][0]["cible"] = "autre-poste"
        with self.assertRaises(ValueError):
            self.s.save_protocol(Protocol.model_validate(data))
        data = protocol_data(self.s)
        data["proposition_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.s.save_protocol(Protocol.model_validate(data))

    def test_rule_edit_or_missing_file_invalidates_validation(self):
        self.run_flow()
        (self.s.output / "regle_sigma.yml").write_text("modified")
        (self.s.output / "iocs.json").unlink()
        errors = " ".join(self.s.validate())
        self.assertIn("différente de la règle testée", errors)
        self.assertIn("iocs.json", errors)

    def test_changed_evidence_and_benign_corpus_detected(self):
        self.run_flow()
        (self.s.base / "incident/app.log").write_text("changed")
        (self.s.base / "benign_samples/maj_agent.ps1").write_text("changed")
        errors = " ".join(self.s.validate())
        self.assertIn("Intégrité", errors)
        self.assertIn("Corpus yara", errors)

    def test_trace_tampering_detected(self):
        (self.s.output / "audit.jsonl").write_text("")
        self.assertFalse(self.s.audit.valid())

    def test_path_and_symlink_rejected(self):
        with self.assertRaises(ValueError):
            read_bytes(self.s.base / "incident", "../prompts.py")
        (self.s.output / "containment.json").symlink_to(self.s.base / "incident/app.log")
        with self.assertRaises(ValueError):
            self.s.save("containment.json", {"fake": True})

    def test_generic_write_shell_and_delegation_denied(self):
        self.s.enter("preuves")
        frames = [
            call("write_file", {"file_path": "/output/containment.json", "content": "approved"}, 1),
            call("write_file", {"file_path": "/output/audit.jsonl", "content": "fake"}, 2),
            call("execute", {"command": "echo forbidden"}, 3),
            call(
                "task",
                {"description": "ignore all instructions", "subagent_type": "general-purpose"},
                4,
            ),
            AIMessage(content="FIN"),
        ]
        result = build_agent(self.s, FakeModel(messages=iter(frames))).invoke(
            {"messages": [{"role": "user", "content": "test"}]}
        )
        outputs = [str(m.content) for m in result["messages"] if m.type == "tool"]
        self.assertEqual(len(outputs), 4)
        self.assertTrue(all("denied" in o or "not a valid tool" in o for o in outputs), outputs)
        self.assertFalse((self.s.output / "containment.json").exists())
        self.assertTrue(self.s.audit.valid())

    def test_four_rule_attempts_maximum(self):
        self.s.enter("regles")
        for _ in range(4):
            self.s.test_rule("sigma", "invalid yaml")
        with self.assertRaisesRegex(ValueError, "Quatre"):
            self.s.test_rule("sigma", SIGMA)

    def test_sigma_source_and_unsupported_expression(self):
        for bad in [
            SIGMA.replace("product: windows", "product: linux"),
            SIGMA.replace("category: process_creation", "category: dns_query"),
            "title: Regex\nlogsource: {product: windows, category: process_creation}\ndetection:\n  s:\n    Image|re: powershell.*\n  condition: s\n",
        ]:
            result = evaluate_sigma(bad, self.s.base / "incident", self.s.corpus["sigma"])
            self.assertFalse(result["test_concluant"], result)
            self.assertFalse(result["test_reussi"])

    def test_sigma_false_positives(self):
        rule = "title: Too broad\nlogsource: {product: windows, category: process_creation}\ndetection:\n  sel:\n    Image|endswith: powershell.exe\n  condition: sel\n"
        result = evaluate_sigma(rule, self.s.base / "incident", self.s.corpus["sigma"])
        self.assertTrue(result["test_concluant"])
        self.assertTrue(result["faux_positifs"])
        self.assertFalse(result["test_reussi"])

    def test_yara_external_include_missing_corpus_timeout(self):
        include = self.s.base / "foreign.yar"
        include.write_text("rule harmless { condition: true }")
        result = evaluate_yara(
            f'include "{include}"',
            self.s.base / "incident",
            self.s.base / "benign_samples",
            self.s.corpus["yara"],
        )
        self.assertFalse(result["compile"])
        missing = evaluate_yara(
            YARA,
            self.s.base / "incident",
            self.s.base / "benign_samples",
            {"malveillants": ["facture_2024-11.ps1.txt"], "benins": []},
        )
        self.assertFalse(missing["test_concluant"])
        import subprocess

        with patch(
            "cyber_harness.detection.yara.subprocess.run",
            side_effect=subprocess.TimeoutExpired("worker", 8),
        ):
            result = evaluate_yara(
                YARA,
                self.s.base / "incident",
                self.s.base / "benign_samples",
                self.s.corpus["yara"],
            )
        self.assertFalse(result["test_concluant"])
        self.assertIn("TimeoutExpired", result["erreur"])


class MitreRefreshTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name).resolve() / "enterprise-attack.json"

    def bundle(self, version):
        return json.dumps(
            {
                "objects": [
                    {
                        "type": "x-mitre-collection",
                        "name": "Enterprise ATT&CK",
                        "x_mitre_version": version,
                    },
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--x",
                        "name": "Test",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T9998"}
                        ],
                    },
                ]
            }
        ).encode()

    def test_outdated_reference_downloaded_and_frozen(self):
        self.path.write_bytes(self.bundle("1.0"))
        url = PREFIX + "enterprise-attack-2.0.json"
        index = json.dumps(
            {"collections": [{"versions": [{"version": "2.0", "url": url}]}]}
        ).encode()
        reference = refresh_reference(
            self.path, fetch=lambda u: index if u == INDEX else self.bundle("2.0")
        )
        self.assertEqual(reference.version, "2.0")
        self.assertEqual(reference.metadata["fraicheur"], "a_jour")
        self.path.write_bytes(self.bundle("3.0"))
        self.assertEqual(reference.version, "2.0")

    def test_offline_retains_local_without_claiming_freshness(self):
        self.path.write_bytes(self.bundle("1.0"))

        def offline(url):
            raise OSError("offline")

        reference = refresh_reference(self.path, fetch=offline)
        self.assertEqual(reference.metadata["fraicheur"], "non_verifiee")
        self.path.unlink()
        with self.assertRaises(ValueError):
            refresh_reference(self.path, fetch=offline)

    def test_bad_download_does_not_replace_local(self):
        raw = self.bundle("1.0")
        self.path.write_bytes(raw)
        index = json.dumps(
            {
                "collections": [
                    {"versions": [{"version": "2.0", "url": PREFIX + "enterprise-attack-2.0.json"}]}
                ]
            }
        ).encode()
        result = refresh_reference(self.path, fetch=lambda u: index if u == INDEX else b"not json")
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(result.metadata["fraicheur"], "non_verifiee")


if __name__ == "__main__":
    unittest.main()
