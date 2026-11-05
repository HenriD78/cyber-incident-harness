"""Réponses fournisseur simulées : aucune connexion Ollama et aucune preuve exécutée."""

import asyncio
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, LLMResult

from cyber_harness.runtime.control import ExecutionMonitor
from cyber_harness.runtime.diagnostics import (
    DiagnosticChatOllama,
    TransportSummary,
    parse_writer_envelope,
    response_diagnostic,
)
from cyber_harness.workflow import build_agent, invoke_phase, run_workflow
from tests.harness_fixtures import FakeModel, analysis_data, session_fixture


def raw(content="", *, thinking="", calls=None, done=True):
    return {
        "model": "synthetic",
        "message": {
            "role": "assistant",
            "content": content,
            "thinking": thinking,
            "tool_calls": calls or [],
        },
        "done": done,
        "done_reason": "stop",
        "eval_count": 2400,
        "prompt_eval_count": 21000,
    }


class ModelDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)

    def events(self):
        return [
            json.loads(line) for line in (self.s.output / "audit.jsonl").read_text().splitlines()
        ]

    def test_transport_accumulates_stream_without_retaining_thinking(self):
        summary = TransportSummary(stream=True, reasoning=None)
        summary.observe(raw(thinking="private", done=False))
        summary.observe(raw(content="hi", done=False))
        final = summary.observe(raw())["td3_transport"]
        self.assertEqual(final["caracteres_thinking"], 7)
        self.assertEqual(final["caracteres_content"], 2)
        self.assertEqual(final["fragments"], 3)
        self.assertNotIn("private", json.dumps(final))

    def test_classification_does_not_guess_from_token_counts(self):
        message = AIMessage(content="", response_metadata={"eval_count": 2400})
        self.assertEqual(
            response_diagnostic(message)["categorie"], "reponse_vide_cause_indeterminee"
        )
        cases = [
            (raw("  "), "reponse_fournisseur_vide"),
            (raw(thinking="private"), "raisonnement_seul"),
            (raw("lost"), "perte_conversion"),
            (
                raw(calls=[{"function": {"name": "save_analysis", "arguments": {}}}]),
                "perte_conversion",
            ),
        ]
        for item, expected in cases:
            with self.subTest(expected=expected):
                summary = TransportSummary(stream=False, reasoning=None).observe(item)[
                    "td3_transport"
                ]
                msg = AIMessage(content="", response_metadata={"td3_transport": summary})
                self.assertEqual(response_diagnostic(msg)["categorie"], expected)
        self.assertEqual(response_diagnostic(AIMessage(content="ok"))["categorie"], "exploitable")
        valid = AIMessage(content="", tool_calls=[{"name": "x", "args": {}, "id": "1"}])
        self.assertEqual(response_diagnostic(valid)["categorie"], "exploitable")
        invalid = AIMessage(
            content="",
            invalid_tool_calls=[{"name": "x", "args": "{", "id": "1", "error": "invalid json"}],
        )
        self.assertEqual(response_diagnostic(invalid)["categorie"], "appel_outil_malforme")

    def test_audit_preserves_tool_calls_and_usage_but_masks_reasoning(self):
        msg = AIMessage(
            content="",
            tool_calls=[{"name": "x", "args": {}, "id": "1"}],
            additional_kwargs={"reasoning_content": "private reasoning"},
            usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        )
        self.s.audit.on_llm_end(
            LLMResult(generations=[[ChatGeneration(message=msg)]]), run_id=uuid4()
        )
        saved = self.events()[-1]["donnees"]["generations"][0][0]["message"]
        self.assertEqual(saved["tool_calls"][0]["name"], "x")
        self.assertEqual(saved["usage_metadata"]["total_tokens"], 15)
        self.assertEqual(saved["additional_kwargs"]["reasoning_content"], "[MASQUÉ]")
        self.assertTrue(self.s.audit.valid())

    def test_real_adapter_empty_stream_then_nonstream_save_analysis(self):
        self.s.enter("preuves")
        for name, lines in self.s.evidence.content.items():
            for start in range(1, len(lines) + 1, 200):
                self.s.evidence.page(name, start, 200)
        model = DiagnosticChatOllama(model="synthetic")
        calls = []
        frames = [
            [raw(thinking="private reasoning", done=False), raw()],
            raw(
                calls=[
                    {
                        "function": {
                            "name": "save_analysis",
                            "arguments": {"analysis": analysis_data(self.s)},
                        }
                    }
                ]
            ),
            raw(content="FIN"),
        ]

        def chat(**kwargs):
            calls.append(kwargs)
            frame = frames.pop(0)
            return iter(frame) if kwargs["stream"] else frame

        monitor = ExecutionMonitor(20, progress=lambda *a, **k: None)
        with patch.object(model._client, "chat", side_effect=chat), redirect_stdout(io.StringIO()):
            agent = build_agent(self.s, model)
            attempts = invoke_phase(self.s, agent, {"callbacks": [self.s.audit, monitor]})
        self.assertEqual(attempts, 2)
        self.assertEqual(monitor.model_calls, 3)
        self.assertTrue(calls[0]["stream"])
        self.assertFalse(calls[1]["stream"])
        self.assertIs(calls[1]["think"], False)
        self.assertFalse(calls[2]["stream"])
        self.assertIsNotNone(self.s.analysis)
        self.assertTrue((self.s.output / "chronologie.md").exists())
        diagnostics = [e for e in self.events() if e["type"] == "diagnostic_reponse_modele"]
        self.assertEqual(diagnostics[0]["donnees"]["categorie"], "raisonnement_seul")
        self.assertEqual(diagnostics[1]["donnees"]["appels_outils_valides"], 1)
        self.assertEqual(diagnostics[1]["donnees"]["transport"]["appels_outils_bruts"], 1)
        self.assertTrue(diagnostics[0]["parent_run_id"])
        self.assertEqual(diagnostics[0]["donnees"]["phase"], "preuves")
        self.assertEqual(diagnostics[0]["donnees"]["invocation_phase"], 1)
        self.assertEqual(diagnostics[1]["donnees"]["invocation_phase"], 2)
        retry = next(e["donnees"] for e in self.events() if e["type"] == "relance_phase")
        self.assertEqual(retry["outils_enregistrement"], ["save_analysis"])
        self.assertNotIn("private reasoning", (self.s.output / "audit.jsonl").read_text())

    def test_persistent_empty_response_stops_with_specific_cause_and_fallback_report(self):
        decision = Mock()
        monitor = ExecutionMonitor(20, progress=lambda *a, **k: None)
        model = FakeModel(messages=iter([AIMessage(content="") for _ in range(3)]))
        with redirect_stdout(io.StringIO()):
            code = run_workflow(
                self.s, model_factory=lambda *a: model, decide=decision, monitor=monitor
            )
        self.assertEqual(code, 1)
        self.assertEqual(monitor.model_calls, 3)
        self.assertIn(
            "reponse_vide_cause_indeterminee", self.s.phase_status["preuves"]["raisons"][0]
        )
        self.assertEqual(self.s.phase_status["ioc"]["statut"], "bloquee")
        decision.assert_not_called()
        self.assertTrue((self.s.output / "rapport_incident.md").exists())

    def test_two_native_empty_responses_recover_via_validated_json_with_reference_correction(self):
        self.s.enter("preuves")
        for name, lines in self.s.evidence.content.items():
            for start in range(1, len(lines) + 1, 200):
                self.s.evidence.page(name, start, 200)
        valid = {"tool": "save_analysis", "arguments": {"analysis": analysis_data(self.s)}}
        import copy

        wrong = copy.deepcopy(valid)
        wrong["arguments"]["analysis"]["constats"][0]["preuves"][0]["ligne"] = 9999
        frames = [
            [raw()],
            raw(),
            raw(content=json.dumps(wrong)),
            raw(content=json.dumps(valid)),
            raw(content="FIN"),
        ]
        calls = []
        model = DiagnosticChatOllama(model="synthetic")

        def chat(**kwargs):
            calls.append(kwargs)
            if len(calls) == 4:
                self.assertIsNone(self.s.analysis)  # La mauvaise référence n'a pas été acceptée.
            frame = frames.pop(0)
            return iter(frame) if kwargs["stream"] else frame

        monitor = ExecutionMonitor(20, progress=lambda *a, **k: None)
        with patch.object(model._client, "chat", side_effect=chat), redirect_stdout(io.StringIO()):
            attempts = invoke_phase(
                self.s, build_agent(self.s, model), {"callbacks": [self.s.audit, monitor]}
            )
        self.assertEqual(attempts, 3)
        self.assertEqual(monitor.model_calls, 5)
        self.assertTrue(calls[0]["tools"])
        self.assertTrue(calls[1]["tools"])
        self.assertFalse(calls[2].get("tools"))
        self.assertFalse(calls[3].get("tools"))
        self.assertIn("Schémas", calls[2]["messages"][-1]["content"])
        self.assertIn("Termine la phase", calls[4]["messages"][-1]["content"])
        self.assertEqual(self.s.feedback.counts[("preuves", "save_analysis")], 1)
        self.assertEqual(self.s.phase_issues("preuves"), [])
        conversions = [e for e in self.events() if e["type"] == "transport_json"]
        self.assertEqual(len(conversions), 2)
        self.assertTrue(all(e["donnees"]["statut"] == "converti" for e in conversions))
        self.assertTrue(self.s.audit.valid())

    def test_json_envelope_refuses_other_tools_duplicates_and_non_json(self):
        allowed = {"save_analysis"}
        bad = [
            '{"tool":"decide","arguments":{"accepted":true}}',
            '{"tool":"execute","arguments":{"command":"echo no"}}',
            '{"tool":"propose_containment","arguments":{}}',
            '{"tool":"save_analysis","arguments":{},"approval":true}',
            '{"tool":"save_analysis","tool":"decide","arguments":{}}',
            '{"tool":"save_analysis","arguments":{"x":NaN}}',
            '[{"tool":"save_analysis","arguments":{}}]',
            '```json\n{"tool":"save_analysis","arguments":{}}\n```',
            '__import__("os").system("echo no")',
        ]
        for content in bad:
            with self.subTest(content=content), self.assertRaises(ValueError):
                parse_writer_envelope(content, allowed)

    def test_json_transport_cannot_forge_approval_or_dispatch_unadvertised_tool(self):
        self.s.enter("preuves")
        model = DiagnosticChatOllama(model="synthetic")
        frames = [[raw()], raw(), raw(content='{"tool":"decide","arguments":{"accepted":true}}')]

        def chat(**kwargs):
            frame = frames.pop(0)
            return iter(frame) if kwargs["stream"] else frame

        from cyber_harness.runtime.feedback import IncompletePhaseError

        with patch.object(model._client, "chat", side_effect=chat), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(IncompletePhaseError, "json_transport_invalide"):
                invoke_phase(self.s, build_agent(self.s, model), {"callbacks": [self.s.audit]})
        self.assertIsNone(self.s.decision)
        self.assertIsNone(self.s.analysis)
        self.assertFalse((self.s.output / "decision_humaine.json").exists())
        self.assertFalse(
            any(
                e["type"] == "outil_entree" and e["donnees"]["nom"] == "decide"
                for e in self.events()
            )
        )
        self.assertTrue(
            any(
                e["type"] == "transport_json" and e["donnees"]["statut"] == "refuse"
                for e in self.events()
            )
        )

    def test_async_transport_is_instrumented(self):
        model = DiagnosticChatOllama(model="synthetic")

        async def chat(**kwargs):
            return raw(thinking="private async reasoning")

        async def invoke():
            with patch.object(model._async_client, "chat", side_effect=chat):
                return await model.ainvoke([HumanMessage(content="test")], stream=False)

        msg = asyncio.run(invoke())
        self.assertEqual(response_diagnostic(msg)["categorie"], "raisonnement_seul")
        self.assertFalse(msg.response_metadata["td3_transport"]["stream"])


if __name__ == "__main__":
    unittest.main()
