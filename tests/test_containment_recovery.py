"""Rejouer les trois refus réels de confinement sans assouplir les cibles."""

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock

from cyber_harness.models import IOC, Analysis, Proposal
from cyber_harness.runtime.control import ExecutionMonitor
from cyber_harness.workflow import run_workflow
from tests.harness_fixtures import AIMessage, FakeModel, call, factory, session_fixture

CASE = json.loads((Path(__file__).parent / "fixtures/containment_trace_case.json").read_text())


def exact_iocs(s):
    return [
        {
            **item,
            "references": s.evidence.occurrences(item["valeur"]),
            "contexte": "Fixture de test issue du run",
            "confiance": "haute",
        }
        for item in CASE["targets"]
    ]


def corrected_call():
    args = copy.deepcopy(CASE["calls"][2])
    # Correction explicite du modèle simulé : aucune normalisation par le harness.
    args["proposal"]["actions"][1]["cible"] = "admin"
    return args


class ContainmentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)
        self.s.enter("preuves")
        for name, lines in self.s.evidence.content.items():
            for start in range(1, len(lines) + 1, 200):
                self.s.evidence.page(name, start, 200)
        self.s.save_analysis(Analysis.model_validate(CASE["analysis"]))
        self.s.enter("ioc")
        values = exact_iocs(self.s)
        for item in values:
            self.s.verify(item["valeur"])
        self.s.save_iocs([IOC.model_validate(item) for item in values])
        self.s.enter("confinement")
        self.tool = next(t for t in self.s.stage_tools() if t.name == "propose_containment")

    def invoke(self, args, index):
        return self.tool.invoke(
            {"name": self.tool.name, "args": args, "id": str(index), "type": "tool_call"}
        )

    def test_real_second_call_reports_both_wrong_references_and_noncanonical_target(self):
        first = self.invoke(CASE["calls"][0], 1)
        self.assertEqual(first.status, "error")
        error = json.loads(first.content)
        fields = {e["champ"] for e in error["erreurs"]}
        self.assertTrue(
            {
                "proposal.actions.*.id",
                "proposal.actions.*.action",
                "proposal.actions.*.preuves",
                "proposal.actions.*.cstdlib",
                "proposal.preuves",
            }
            <= fields
        )
        context = error["contexte_confinement"]
        self.assertIn("admin", [i["cible"] for i in context["cibles_ioc_verifiees"]])
        self.assertEqual(
            error["exemple_structure"]["proposal"]["actions"][0]["cible"], "203.0.113.42"
        )

        second = self.invoke(CASE["calls"][1], 2)
        errors = json.loads(second.content)["erreurs"]
        by_field = {e["champ"]: e for e in errors}
        self.assertEqual(
            set(by_field),
            {
                "proposal.actions.1.preuves",
                "proposal.actions.1.cible",
                "proposal.actions.2.preuves",
            },
        )
        self.assertEqual(by_field["proposal.actions.1.cible"]["valeur"], "compte admin")
        self.assertIn("admin", by_field["proposal.actions.1.cible"]["cibles_ioc_verifiees"])
        self.assertCountEqual(
            by_field["proposal.actions.1.preuves"]["references_attendues"],
            [
                self.s.evidence.reference("web_access.log", 43),
                self.s.evidence.reference("app.log", 7),
            ],
        )
        self.assertIsNone(self.s.proposal)
        self.assertIsNone(self.s.decision)
        self.assertFalse((self.s.output / "proposition_confinement.json").exists())

        fixed = self.invoke(corrected_call(), 3)
        self.assertEqual(fixed.status, "success")
        self.assertEqual(self.s.feedback.counts[("confinement", "propose_containment")], 2)
        self.assertEqual(self.s.proposal.actions[1].cible, "admin")
        self.assertIsNone(self.s.decision)  # Une proposition valide n'est pas une approbation.
        self.assertFalse((self.s.output / "containment.json").exists())

    def test_original_third_call_stays_rejected_without_silent_target_rewrite(self):
        original = copy.deepcopy(CASE["calls"][2])
        reply = self.invoke(original, 1)
        errors = json.loads(reply.content)["erreurs"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["champ"], "proposal.actions.1.cible")
        self.assertEqual(original["proposal"]["actions"][1]["cible"], "compte admin")
        self.assertIsNone(self.s.proposal)

    def test_unknown_partial_and_combined_targets_are_rejected(self):
        for target in (
            "203.0.113.4",
            "admin2",
            "compte admin",
            "203.0.113.42, 8.8.8.8",
            "PC-COMPTA-08",
        ):
            args = corrected_call()
            args["proposal"]["actions"][0]["cible"] = target
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(ValueError, "Cible non vérifiée"),
            ):
                self.s.propose(Proposal.model_validate(args["proposal"]))
            self.assertIsNone(self.s.proposal)

    def test_exact_target_from_evidence_remains_allowed_without_being_an_ioc(self):
        args = corrected_call()
        args["proposal"]["actions"][1]["cible"] = "web-01"
        self.assertNotIn("web-01", [i.valeur for i in self.s.iocs])
        self.s.propose(Proposal.model_validate(args["proposal"]))
        self.assertEqual(self.s.proposal.actions[1].cible, "web-01")
        self.assertIsNone(self.s.decision)

    def test_three_invalid_targets_still_stop_without_proposal_or_approval(self):
        from cyber_harness.runtime.feedback import PhaseRecoveryLimitError

        with redirect_stdout(io.StringIO()):
            self.invoke(CASE["calls"][2], 1)
            self.invoke(CASE["calls"][2], 2)
            with self.assertRaisesRegex(PhaseRecoveryLimitError, "3 appels invalides"):
                self.invoke(CASE["calls"][2], 3)
        self.assertEqual(self.s.feedback.counts[("confinement", "propose_containment")], 3)
        self.assertIsNone(self.s.proposal)
        self.assertIsNone(self.s.decision)
        self.assertFalse((self.s.output / "proposition_confinement.json").exists())
        self.assertFalse((self.s.output / "containment.json").exists())

    def test_hypothesis_and_modified_evidence_still_block_proposal(self):
        self.s.analysis.constats[0].statut = "hypothese"
        with self.assertRaisesRegex(ValueError, "hypothèse"):
            self.s.propose(Proposal.model_validate(corrected_call()["proposal"]))
        self.s.analysis.constats[0].statut = "observe"
        (self.s.base / "incident/app.log").write_text("modified")
        with self.assertRaisesRegex(ValueError, "Preuves modifiées"):
            self.s.propose(Proposal.model_validate(corrected_call()["proposal"]))
        self.assertIsNone(self.s.proposal)

    def test_forged_approval_is_rejected_and_duplicate_proposal_stays_forbidden(self):
        args = corrected_call()
        args["proposal"]["approved"] = True
        reply = self.invoke(args, 1)
        self.assertEqual(reply.status, "error")
        self.assertIsNone(self.s.decision)
        self.assertFalse((self.s.output / "containment.json").exists())
        self.invoke(corrected_call(), 2)
        original = self.s.proposal.model_dump()
        with self.assertRaisesRegex(ValueError, "Une seule proposition"):
            self.s.propose(Proposal.model_validate(corrected_call()["proposal"]))
        self.assertEqual(self.s.proposal.model_dump(), original)
        self.assertIsNone(self.s.decision)


class ContainmentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)

    def flow(self, accepted):
        phases = []

        def create(stage, s):
            phases.append(stage)
            if stage == "preuves":
                frames = [
                    call(
                        "read_evidence",
                        {"fichier": name, "debut": start, "limite": 200},
                        f"{name}-{start}",
                    )
                    for name, lines in s.evidence.content.items()
                    for start in range(1, len(lines) + 1, 200)
                ]
                frames += [
                    call("save_analysis", {"analysis": CASE["analysis"]}, "save"),
                    AIMessage(content="FIN"),
                ]
            elif stage == "ioc":
                values = exact_iocs(s)
                frames = [
                    call("verify_ioc", {"value": i["valeur"]}, n) for n, i in enumerate(values)
                ]
                frames += [call("save_iocs", {"iocs": values}, "save"), AIMessage(content="FIN")]
            elif stage == "confinement":
                frames = [
                    call("propose_containment", args, n)
                    for n, args in enumerate([*CASE["calls"][:2], corrected_call()])
                ]
                frames += [AIMessage(content="FIN")]
            elif stage == "protocole":
                protocol = {
                    "proposition_sha256": s.decision["proposition_sha256"],
                    "actions": [
                        {
                            "action_id": a.id,
                            "cible": a.cible,
                            "responsable": "Équipe de test",
                            **{
                                k: ["Consigne manuelle fictive à confirmer"]
                                for k in (
                                    "prerequis",
                                    "etapes",
                                    "verifications",
                                    "criteres_arret",
                                    "retour_arriere",
                                )
                            },
                        }
                        for a in s.proposal.actions
                    ],
                }
                frames = [
                    call("save_protocol", {"protocol": protocol}, "save"),
                    AIMessage(content="FIN"),
                ]
            else:
                return factory(stage, s)
            return FakeModel(messages=iter(frames))

        decision = Mock(return_value=(accepted, "test"))
        monitor = ExecutionMonitor(120, progress=lambda *a, **k: None)
        with redirect_stdout(io.StringIO()):
            code = run_workflow(self.s, model_factory=create, decide=decision, monitor=monitor)
        return code, phases, decision

    def test_real_errors_corrected_before_acceptance_protocol_and_report(self):
        code, phases, decision = self.flow(True)
        self.assertEqual(code, 0, self.s.validate())
        decision.assert_called_once()
        self.assertEqual(self.s.feedback.counts[("confinement", "propose_containment")], 2)
        self.assertEqual(self.s.decision["decision"], "acceptee")
        self.assertIn("protocole", phases)
        self.assertEqual(len(self.s.protocol.actions), 3)
        self.assertEqual(
            [a.cible for a in self.s.protocol.actions], ["203.0.113.42", "admin", "PC-COMPTA-07"]
        )
        self.assertEqual(self.s.phase_status["rapport"]["statut"], "terminee")
        self.assertTrue(self.s.audit.valid())

    def test_real_errors_corrected_before_refusal_report_without_protocol(self):
        code, phases, decision = self.flow(False)
        self.assertEqual(code, 0, self.s.validate())
        decision.assert_called_once()
        self.assertEqual(self.s.decision["decision"], "refusee")
        self.assertNotIn("protocole", phases)
        self.assertIsNone(self.s.protocol)
        self.assertFalse((self.s.output / "protocole_confinement.json").exists())
        self.assertEqual(self.s.phase_status["rapport"]["statut"], "terminee")


if __name__ == "__main__":
    unittest.main()
