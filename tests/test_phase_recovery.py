"""Rejouer line_text'échec réel de save_analysis et vérifier les barrières entre phases."""

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock

from cyber_harness.models import Analysis
from cyber_harness.runtime.control import ExecutionMonitor
from cyber_harness.runtime.feedback import (
    MAX_INVALID_CALLS,
    MAX_PHASE_INVOCATIONS,
)
from cyber_harness.workflow import build_agent, run_workflow
from tests.harness_fixtures import (
    SIGMA,
    AIMessage,
    FakeModel,
    analysis_data,
    call,
    factory,
    prepare_analysis,
    proposal_data,
    session_fixture,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures/malformed_analysis_call.json").read_text())
IOC_FIXTURE = json.loads((Path(__file__).parent / "fixtures/incomplete_iocs_call.json").read_text())


def evidence_frames(s):
    return [
        call("read_evidence", {"fichier": name, "debut": start, "limite": 200}, f"{name}-{start}")
        for name, lines in s.evidence.content.items()
        for start in range(1, len(lines) + 1, 200)
    ]


class PhaseRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)

    def flow(self, create, *, accepted=False):
        phases = []

        def record(stage, session):
            phases.append(stage)
            return create(stage, session)

        decision = Mock(return_value=(accepted, "test"))
        monitor = ExecutionMonitor(120, progress=lambda *a, **k: None)
        with redirect_stdout(io.StringIO()):
            code = run_workflow(self.s, model_factory=record, decide=decision, monitor=monitor)
        return code, phases, decision, monitor

    def test_real_malformed_call_returns_actionable_error_without_saving(self):
        self.s.enter("preuves")
        tool = next(t for t in self.s.stage_tools() if t.name == "save_analysis")
        result = tool.invoke(
            {
                "name": tool.name,
                "args": FIXTURE["arguments"],
                "id": "bad-analysis",
                "type": "tool_call",
            }
        )
        self.assertEqual(result.status, "error")
        feedback = json.loads(result.content)
        fields = {e["champ"] for e in feedback["erreurs"]}
        self.assertTrue(
            {
                "analysis.constats.*.id",
                "analysis.constats.*.preuves",
                "analysis.qualifications",
                "analysis.limites",
            }.issubset(fields)
        )
        self.assertEqual(
            next(
                e["occurrences"]
                for e in feedback["erreurs"]
                if e["champ"] == "analysis.constats.*.id"
            ),
            10,
        )
        example = feedback["exemple_structure"]["analysis"]
        Analysis.model_validate(example)  # Gabarit conforme au schéma ; pas un constat accepté.
        self.assertIn("qualifications", example)
        self.assertIsNone(self.s.analysis)
        self.assertFalse((self.s.output / "analyse.json").exists())
        self.assertEqual(feedback["constats_disponibles"], [])

    def test_malformed_analysis_then_corrected_call_in_same_invocation(self):
        def create(stage, s):
            if stage != "preuves":
                return factory(stage, s)
            frames = evidence_frames(s) + [
                call("save_analysis", FIXTURE["arguments"], "bad"),
                call("save_analysis", {"analysis": analysis_data(s)}, "correct"),
                AIMessage(content="FIN"),
            ]
            return FakeModel(messages=iter(frames))

        code, phases, decision, _ = self.flow(create)
        self.assertEqual(code, 0, self.s.validate())
        self.assertEqual(self.s.phase_status["preuves"]["invocations"], 1)
        self.assertEqual(self.s.feedback.counts[("preuves", "save_analysis")], 1)
        self.assertEqual(decision.call_count, 1)
        self.assertEqual(self.s.decision["decision"], "refusee")
        self.assertNotIn("protocole", phases)

    def test_early_finish_after_error_resumes_with_history_and_recovers(self):
        observed = []

        class RecordingModel(FakeModel):
            def _generate(self, messages, *args, **kwargs):
                observed.append(list(messages))
                return super()._generate(messages, *args, **kwargs)

        def create(stage, s):
            if stage != "preuves":
                return factory(stage, s)
            frames = evidence_frames(s) + [
                call("save_analysis", FIXTURE["arguments"], "bad"),
                AIMessage(content="FIN"),
                call("save_analysis", {"analysis": analysis_data(s)}, "correct"),
                AIMessage(content="FIN"),
            ]
            return RecordingModel(messages=iter(frames))

        code, _, _, monitor = self.flow(create)
        self.assertEqual(code, 0, self.s.validate())
        self.assertEqual(self.s.phase_status["preuves"]["invocations"], 2)
        retry_messages = next(
            messages
            for messages in observed
            if messages[-1].type == "human" and "non_terminee" in str(messages[-1].content)
        )
        self.assertTrue(
            any(
                m.type == "tool" and m.name == "save_analysis" and m.status == "error"
                for m in retry_messages
            )
        )
        self.assertTrue(any(m.type == "tool" and m.name == "read_evidence" for m in retry_messages))
        self.assertGreater(monitor.model_calls, 2)
        events = [
            json.loads(line_text)
            for line_text in (self.s.output / "audit.jsonl").read_text().splitlines()
        ]
        self.assertTrue(any(e["type"] == "relance_phase" for e in events))

    def test_changing_malformed_calls_still_hit_recovery_limit(self):
        def create(stage, s):
            self.assertEqual(stage, "preuves")
            frames = []
            for n in range(MAX_INVALID_CALLS + 2):
                args = copy.deepcopy(FIXTURE["arguments"])
                args["analysis"]["constats"][0]["description"] += f" variante {n}"
                frames.append(call("save_analysis", args, n))
            return FakeModel(messages=iter(frames))

        code, phases, decision, monitor = self.flow(create)
        self.assertEqual(code, 1)
        self.assertEqual(phases, ["preuves"])
        self.assertEqual(monitor.model_calls, MAX_INVALID_CALLS)
        self.assertEqual(self.s.phase_status["preuves"]["statut"], "echec")
        for phase in ("ioc", "mitre", "regles", "confinement"):
            self.assertEqual(self.s.phase_status[phase]["statut"], "bloquee")
        self.assertEqual(self.s.phase_status["rapport"]["statut"], "secours")
        decision.assert_not_called()
        self.assertIsNone(self.s.summary)
        self.assertTrue((self.s.output / "rapport_incident.md").exists())

    def test_model_finishing_without_saving_is_retried_then_blocks_dependents(self):
        def create(stage, s):
            self.assertEqual(stage, "preuves")
            return FakeModel(
                messages=iter([AIMessage(content="FIN") for _ in range(MAX_PHASE_INVOCATIONS + 1)])
            )

        code, phases, decision, monitor = self.flow(create)
        self.assertEqual(code, 1)
        self.assertEqual(phases, ["preuves"])
        self.assertEqual(monitor.model_calls, MAX_PHASE_INVOCATIONS)
        self.assertEqual(self.s.phase_status["preuves"]["invocations"], MAX_PHASE_INVOCATIONS)
        self.assertIn(
            "Livrable non enregistré", " ".join(self.s.phase_status["preuves"]["raisons"])
        )
        decision.assert_not_called()

    def test_failed_iocs_allow_independent_mapping_and_rules_but_block_containment(self):
        def create(stage, s):
            if stage != "ioc":
                return factory(stage, s)
            return FakeModel(
                messages=iter([AIMessage(content="FIN") for _ in range(MAX_PHASE_INVOCATIONS)])
            )

        code, phases, decision, _ = self.flow(create)
        self.assertEqual(code, 1)
        self.assertIn("mitre", phases)
        self.assertIn("regles", phases)
        self.assertIn("rapport", phases)
        self.assertNotIn("confinement", phases)
        self.assertEqual(self.s.phase_status["confinement"]["statut"], "bloquee")
        self.assertIsNotNone(self.s.summary)
        self.assertTrue(self.s.tests["sigma"]["test_reussi"])
        decision.assert_not_called()

    def test_business_error_preserves_invalid_reference_and_provides_feedback(self):
        self.s.enter("preuves")
        for name, lines in self.s.evidence.content.items():
            for start in range(1, len(lines) + 1, 200):
                self.s.evidence.page(name, start, 200)
        args = analysis_data(self.s)
        args["constats"][0]["preuves"][0]["sha256"] = "0" * 64
        tool = next(t for t in self.s.stage_tools() if t.name == "save_analysis")
        result = tool.invoke(
            {"name": tool.name, "args": {"analysis": args}, "id": "bad-sha", "type": "tool_call"}
        )
        feedback = json.loads(result.content)
        self.assertEqual(feedback["code"], "validation_metier")
        self.assertIn("Empreinte", feedback["erreurs"][0]["message"])
        self.assertIsNone(self.s.analysis)
        self.assertFalse((self.s.output / "analyse.json").exists())

    def test_wrong_summary_ids_receive_actual_finding_ids(self):
        prepare_analysis(self.s)
        self.s.enter("rapport")
        tool = next(t for t in self.s.stage_tools() if t.name == "save_report_summary")
        result = tool.invoke(
            {
                "name": tool.name,
                "args": {"summary": {"resume": "Résumé", "constat_ids": ["0" * 64], "limites": []}},
                "id": "bad-summary",
                "type": "tool_call",
            }
        )
        feedback = json.loads(result.content)
        self.assertEqual(feedback["constats_disponibles"][0]["id"], "C1")
        self.assertEqual(feedback["exemple_structure"]["summary"]["constat_ids"], ["C1"])
        self.assertIsNone(self.s.summary)

    def test_permanent_summary_errors_are_bounded_and_keep_partial_report(self):
        def create(stage, s):
            if stage != "rapport":
                return factory(stage, s)
            ids = [
                "0" * 64,
                "facture_2024-11.ps1.txt",
                "ticket_INC-2026-0417.md",
                "edr_events.jsonl",
            ]
            return FakeModel(
                messages=iter(
                    [
                        call(
                            "save_report_summary",
                            {
                                "summary": {
                                    "resume": "Résumé non accepté",
                                    "constat_ids": [value],
                                    "limites": [],
                                }
                            },
                            n,
                        )
                        for n, value in enumerate(ids)
                    ]
                )
            )

        code, _, _, _ = self.flow(create)
        self.assertEqual(code, 1)
        self.assertEqual(
            self.s.feedback.counts[("rapport", "save_report_summary")], MAX_INVALID_CALLS
        )
        self.assertEqual(self.s.phase_status["rapport"]["statut"], "echec")
        self.assertIsNone(self.s.summary)
        report = (self.s.output / "rapport_incident.md").read_text()
        self.assertIn("C1", report)
        self.assertIn("Synthèse non vérifiée", report)

    def test_invalid_containment_can_recover_before_human_refusal(self):
        def create(stage, s):
            if stage != "confinement":
                return factory(stage, s)
            wrong = copy.deepcopy(proposal_data(s))
            wrong["actions"][0]["target"] = wrong["actions"][0].pop("cible")
            del wrong["actions"][0]["id"]
            return FakeModel(
                messages=iter(
                    [
                        call("propose_containment", {"proposal": wrong}, "bad"),
                        call("propose_containment", {"proposal": proposal_data(s)}, "correct"),
                        AIMessage(content="FIN"),
                    ]
                )
            )

        code, phases, decision, _ = self.flow(create)
        self.assertEqual(code, 0, self.s.validate())
        self.assertEqual(decision.call_count, 1)
        self.assertNotIn("protocole", phases)
        self.assertEqual(self.s.decision["decision"], "refusee")

    def test_failed_rules_do_not_hide_independent_containment_and_report(self):
        def create(stage, s):
            if stage != "regles":
                return factory(stage, s)
            frames = [call("validate_sigma", {"rule_yaml": SIGMA}, "sigma")]
            frames += [
                call("test_yara", {"rule_text": f"rule broad_{n} {{ condition: true }}"}, n)
                for n in range(4)
            ]
            return FakeModel(messages=iter(frames + [AIMessage(content="FIN")]))

        code, phases, decision, _ = self.flow(create)
        self.assertEqual(code, 1)
        self.assertEqual(self.s.phase_status["regles"]["statut"], "echec")
        self.assertEqual(self.s.phase_status["regles"]["invocations"], 1)
        self.assertIn("confinement", phases)
        self.assertIn("rapport", phases)
        self.assertEqual(decision.call_count, 1)
        self.assertTrue(self.s.tests["yara"]["faux_positifs"])
        self.assertIsNotNone(self.s.summary)

    def test_deleted_prerequisite_blocks_model_factory_even_if_state_exists(self):
        prepare_analysis(self.s)
        (self.s.output / "analyse.json").unlink()
        self.s.enter("ioc")
        with self.assertRaisesRegex(ValueError, "Phase bloquée"):
            build_agent(self.s, FakeModel(messages=iter([AIMessage(content="FIN")])))

    def ioc_args(self):
        args = copy.deepcopy(IOC_FIXTURE["arguments"])
        for ioc in args["iocs"]:
            # L'analyse synthétique du test ne définit que C1 ; les valeurs et
            # références du lot en échec restent celles de la trace réelle.
            ioc["constat_ids"] = ["C1"]
        return args

    def test_real_incomplete_iocs_report_all_missing_references_and_can_recover(self):
        prepare_analysis(self.s)
        self.s.enter("ioc")
        args = self.ioc_args()
        for ioc in args["iocs"]:
            self.s.verify(ioc["valeur"])
        tool = next(t for t in self.s.stage_tools() if t.name == "save_iocs")
        reply = tool.invoke(
            {"name": tool.name, "args": args, "id": "incomplete-iocs", "type": "tool_call"}
        )
        self.assertEqual(reply.status, "error")
        errors = json.loads(reply.content)["erreurs"]
        by_value = {e["valeur"]: e for e in errors}
        self.assertEqual(set(by_value), {"192.168.1.100", "admin"})
        self.assertEqual(by_value["192.168.1.100"]["champ"], "iocs.1.references")
        self.assertEqual(
            by_value["192.168.1.100"]["references_manquantes"],
            [self.s.evidence.reference("facture_2024-11.ps1.txt", 144)],
        )
        self.assertEqual(by_value["192.168.1.100"]["nombre_attendu"], 3)
        self.assertEqual(len(by_value["admin"]["references_manquantes"]), 9)
        self.assertIsNone(self.s.iocs)
        self.assertFalse((self.s.output / "iocs.json").exists())
        # Corriger uniquement à partir des références exactes du retour d'erreur.
        for error in errors:
            index = int(error["champ"].split(".")[1])
            args["iocs"][index]["references"].extend(error["references_manquantes"])
        fixed = tool.invoke(
            {"name": tool.name, "args": args, "id": "correct-iocs", "type": "tool_call"}
        )
        self.assertEqual(fixed.status, "success")
        self.assertEqual(len(self.s.iocs), 6)
        self.assertEqual(self.s.phase_issues("ioc"), [])
        self.assertEqual(self.s.feedback.counts[("ioc", "save_iocs")], 1)

    def test_incomplete_iocs_corrected_then_human_acceptance_protocol_and_report(self):
        def create(stage, s):
            if stage != "ioc":
                return factory(stage, s)
            args = self.ioc_args()
            fixed = copy.deepcopy(args)
            for ioc in fixed["iocs"]:
                ioc["references"] = s.evidence.occurrences(ioc["valeur"])
            frames = [
                call("verify_ioc", {"value": ioc["valeur"]}, f"verify-{n}")
                for n, ioc in enumerate(args["iocs"])
            ]
            frames += [
                call("save_iocs", args, "incomplete"),
                call("save_iocs", fixed, "correct"),
                AIMessage(content="FIN"),
            ]
            return FakeModel(messages=iter(frames))

        code, phases, decision, _ = self.flow(create, accepted=True)
        self.assertEqual(code, 0, self.s.validate())
        self.assertEqual(self.s.feedback.counts[("ioc", "save_iocs")], 1)
        self.assertEqual(self.s.phase_status["confinement"]["statut"], "terminee")
        self.assertIn("protocole", phases)
        self.assertIsNotNone(self.s.protocol)
        self.assertIsNotNone(self.s.summary)
        decision.assert_called_once()

    def test_ioc_error_distinguishes_missing_verification_from_incomplete_references(self):
        prepare_analysis(self.s)
        self.s.enter("ioc")
        ioc = self.ioc_args()["iocs"][2]
        tool = next(t for t in self.s.stage_tools() if t.name == "save_iocs")
        reply = tool.invoke(
            {"name": tool.name, "args": {"iocs": [ioc]}, "id": "unverified", "type": "tool_call"}
        )
        error = json.loads(reply.content)["erreurs"][0]
        self.assertEqual(
            error["appel_requis"], {"outil": "verify_ioc", "arguments": {"value": ioc["valeur"]}}
        )
        self.assertNotIn("references_manquantes", error)
        self.assertIsNone(self.s.iocs)

    def test_ioc_error_rejects_extra_and_duplicate_references_without_saving(self):
        prepare_analysis(self.s)
        self.s.enter("ioc")
        ioc = self.ioc_args()["iocs"][2]
        self.s.verify(ioc["valeur"])
        duplicate = ioc["references"][0]
        unrelated = self.s.evidence.reference("app.log", 1)
        ioc["references"].extend([duplicate, unrelated])
        tool = next(t for t in self.s.stage_tools() if t.name == "save_iocs")
        reply = tool.invoke(
            {"name": tool.name, "args": {"iocs": [ioc]}, "id": "extra", "type": "tool_call"}
        )
        error = json.loads(reply.content)["erreurs"][0]
        self.assertEqual(error["references_manquantes"], [])
        self.assertCountEqual(error["references_inattendues"], [duplicate, unrelated])
        self.assertIsNone(self.s.iocs)
        self.assertFalse((self.s.output / "iocs.json").exists())

    def test_persistent_incomplete_iocs_still_block_containment_at_three_errors(self):
        def create(stage, s):
            if stage != "ioc":
                return factory(stage, s)
            args = self.ioc_args()
            frames = [
                call("verify_ioc", {"value": ioc["valeur"]}, f"verify-{n}")
                for n, ioc in enumerate(args["iocs"])
            ]
            frames += [call("save_iocs", args, f"bad-{n}") for n in range(MAX_INVALID_CALLS)]
            return FakeModel(messages=iter(frames))

        code, phases, decision, _ = self.flow(create)
        self.assertEqual(code, 1)
        self.assertEqual(self.s.feedback.counts[("ioc", "save_iocs")], MAX_INVALID_CALLS)
        self.assertIsNone(self.s.iocs)
        self.assertNotIn("confinement", phases)
        self.assertEqual(self.s.phase_status["confinement"]["statut"], "bloquee")
        self.assertIn("192.168.1.100", self.s.phase_status["ioc"]["raisons"][0])
        self.assertIn("admin", self.s.phase_status["ioc"]["raisons"][0])
        decision.assert_not_called()


if __name__ == "__main__":
    unittest.main()
