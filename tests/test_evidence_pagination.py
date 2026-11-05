"""Rejouer les offset ignorés du run réel, sans modèle ni réseau externe."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock

from cyber_harness.runtime.control import ExecutionLimitError, ExecutionMonitor
from cyber_harness.workflow import run_workflow
from tests.harness_fixtures import (
    AIMessage,
    FakeModel,
    analysis_data,
    call,
    factory,
    session_fixture,
)

READS = json.loads((Path(__file__).parent / "fixtures/offset_evidence_reads.json").read_text())[
    "read_evidence_calls"
]
SCRIPT = "facture_2024-11.ps1.txt"


class EvidencePaginationTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)
        self.s.enter("preuves")
        self.tool = next(t for t in self.s.stage_tools() if t.name == "read_evidence")

    def test_original_captured_reads_now_cover_the_entire_script(self):
        pages = [self.tool.invoke(args) for args in READS]
        self.assertEqual(pages[4]["lignes"][0]["ligne"], 1)
        self.assertEqual(pages[5]["lignes"][0]["ligne"], 102)  # offset=101 est à partir de 0.
        self.assertEqual(pages[5]["lecture_suivante"]["debut"], 101)  # Trou entre les pages.
        self.assertEqual(pages[6]["lignes"][0]["ligne"], 101)
        self.assertEqual(pages[-1]["lignes"][-1]["ligne"], 206)
        self.assertTrue(pages[-1]["couverture"]["complete"])
        self.assertIsNone(pages[-1]["lecture_suivante"])
        self.assertTrue(self.s.evidence.complete())
        self.assertIsNone(self.s.analysis)  # Lecture complète != analyse enregistrée.

    def test_zero_based_offset_and_one_based_debut_are_equivalent(self):
        by_offset = self.tool.invoke({"fichier": SCRIPT, "offset": 100, "limite": 2})
        by_line = self.tool.invoke({"fichier": SCRIPT, "debut": 101, "limite": 2})
        self.assertEqual(by_offset["lignes"], by_line["lignes"])
        self.assertEqual([r["ligne"] for r in by_offset["lignes"]], [101, 102])
        self.assertEqual(by_line["couverture"]["nouvelles_lignes"], 0)
        first = self.tool.invoke({"fichier": SCRIPT, "offset": 0, "limite": 1})
        self.assertEqual(first["lignes"][0]["ligne"], 1)

    def test_reaching_end_does_not_hide_unread_earlier_pages(self):
        page = self.tool.invoke({"fichier": SCRIPT, "offset": 200})
        self.assertIsNone(page["prochaine_ligne"])
        self.assertFalse(page["couverture"]["complete"])
        self.assertEqual(page["lecture_suivante"], {"fichier": SCRIPT, "debut": 1, "limite": 200})
        self.assertEqual(self.s.feedback.example("read_evidence")["debut"], 1)
        self.assertTrue(self.s.feedback.context()["lectures_restantes"])
        self.assertFalse(self.s.evidence.complete())

    def test_ambiguous_or_negative_pagination_is_rejected_before_reading(self):
        for index, args in enumerate(
            ({"fichier": SCRIPT, "debut": 101, "offset": 100}, {"fichier": SCRIPT, "offset": -1})
        ):
            with self.subTest(args=args):
                reply = self.tool.invoke(
                    {"name": self.tool.name, "args": args, "id": str(index), "type": "tool_call"}
                )
                self.assertEqual(reply.status, "error")
                self.assertEqual(json.loads(reply.content)["code"], "validation_metier")
        self.assertEqual(self.s.evidence.covered[SCRIPT], set())

    def test_unknown_parameter_is_not_silently_ignored(self):
        with redirect_stdout(io.StringIO()):
            reply = self.tool.invoke(
                {
                    "name": self.tool.name,
                    "args": {"fichier": SCRIPT, "offest": 100},
                    "id": "typo",
                    "type": "tool_call",
                }
            )
        error = json.loads(reply.content)
        self.assertEqual(reply.status, "error")
        self.assertEqual(error["code"], "arguments_invalides")
        self.assertEqual(error["erreurs"][0]["champ"], "offest")
        self.assertEqual(error["erreurs"][0]["type"], "extra_forbidden")
        self.assertEqual(self.s.evidence.covered[SCRIPT], set())


class PaginationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)

    def test_captured_reads_can_finish_analysis_and_reach_human_decision(self):
        def create(stage, s):
            if stage != "preuves":
                return factory(stage, s)
            frames = [call("read_evidence", args, n) for n, args in enumerate(READS)]
            frames += [
                call("save_analysis", {"analysis": analysis_data(s)}, "save"),
                AIMessage(content="FIN"),
            ]
            return FakeModel(messages=iter(frames))

        decision = Mock(return_value=(False, "test"))
        monitor = ExecutionMonitor(80, progress=lambda *a, **k: None)
        with redirect_stdout(io.StringIO()):
            code = run_workflow(self.s, model_factory=create, decide=decision, monitor=monitor)
        self.assertEqual(code, 0, self.s.validate())
        self.assertTrue(self.s.evidence.complete())
        self.assertEqual(self.s.phase_status["preuves"]["statut"], "terminee")
        decision.assert_called_once()

    def test_real_repeat_loop_still_stops_and_keeps_its_cause_after_report(self):
        def create(stage, s):
            self.assertEqual(stage, "preuves")
            return FakeModel(
                messages=iter(
                    [
                        call("read_evidence", {"fichier": SCRIPT, "offset": 106, "limite": 100}, n)
                        for n in range(6)
                    ]
                )
            )

        decision = Mock()
        monitor = ExecutionMonitor(50, progress=lambda *a, **k: None)
        with redirect_stdout(io.StringIO()):
            code = run_workflow(self.s, model_factory=create, decide=decision, monitor=monitor)
        self.assertEqual(code, 1)
        self.assertEqual(monitor.model_calls, 4)
        self.assertFalse(self.s.evidence.complete())
        diagnostic = json.loads((self.s.output / "diagnostic_execution.json").read_text())
        self.assertIn("Boucle détectée : read_evidence", diagnostic["raison_arret"])
        self.assertEqual(self.s.phase_status["rapport"]["statut"], "secours")
        self.assertTrue((self.s.output / "rapport_incident.md").exists())
        decision.assert_not_called()

    def test_report_mode_releases_reserve_without_erasing_original_stop_reason(self):
        monitor = ExecutionMonitor(10, repeat_limit=2, progress=lambda *a, **k: None)
        monitor.on_tool_start({"name": "read_evidence"}, "{}")
        with self.assertRaises(ExecutionLimitError):
            monitor.on_tool_start({"name": "read_evidence"}, "{}")
        reason = monitor.snapshot()["raison_arret"]
        monitor.begin_report()
        monitor.on_chat_model_start({}, [])
        self.assertEqual(monitor.model_calls, 1)
        self.assertEqual(monitor.snapshot()["raison_arret"], reason)


if __name__ == "__main__":
    unittest.main()
