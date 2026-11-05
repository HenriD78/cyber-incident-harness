"""Rejoue un lot capturé dans LangSmith avec des outils factices, sans Ollama."""

import asyncio
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from deepagents import create_deep_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver

import cyber_harness.workflow as td3
from cyber_harness.runtime.control import (
    DeduplicateReadonlyToolCalls,
    ExecutionLimitError,
    ExecutionMonitor,
    deduplicate_readonly_calls,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures/duplicate_ioc_tool_calls.json").read_text())


class FakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def quiet(*args, **kwargs):
    pass


def batch():
    return AIMessage(id=FIXTURE["message_id"], content="", tool_calls=FIXTURE["tool_calls"])


class DeduplicationTests(unittest.TestCase):
    def setUp(self):
        self.effects = []

        @tool
        def verify_ioc(value: str) -> str:
            """Verify a synthetic indicator, without accessing any evidence file."""
            self.effects.append(value)
            return "synthetic verification result"

        self.verify = verify_ioc

    def make_agent(self, messages, *, deduplicate=True):
        return create_deep_agent(
            model=FakeModel(messages=iter(messages)),
            tools=[self.verify],
            middleware=[DeduplicateReadonlyToolCalls()] if deduplicate else [],
        )

    def config(self):
        return {"callbacks": [ExecutionMonitor(20, progress=quiet)], "recursion_limit": 400}

    def test_original_captured_batch_reproduces_the_abort(self):
        agent = self.make_agent([batch(), AIMessage(content="DONE")], deduplicate=False)
        with self.assertRaises(ExecutionLimitError):
            agent.invoke(
                {"messages": [{"role": "user", "content": "synthetic test"}]}, config=self.config()
            )
        self.assertEqual(len(self.effects), 3)

    def test_captured_batch_executes_once_and_finishes(self):
        original = batch()
        with redirect_stdout(io.StringIO()):
            result = self.make_agent([original, AIMessage(content="DONE")]).invoke(
                {"messages": [{"role": "user", "content": "synthetic test"}]},
                config=self.config(),
            )
        self.assertEqual(self.effects, ["203.0.113.42"])
        self.assertEqual(result["messages"][-1].content, "DONE")
        # L'historique transmis au prochain LLM reste un protocole valide :
        # un seul appel conservé et une réponse avec le même tool_call_id.
        ai = next(m for m in result["messages"] if m.id == original.id)
        outputs = [m for m in result["messages"] if isinstance(m, ToolMessage)]
        self.assertEqual(len(ai.tool_calls), 1)
        self.assertEqual([m.tool_call_id for m in outputs], [ai.tool_calls[0]["id"]])
        self.assertEqual(len(original.tool_calls), 6)
        self.assertEqual(len(ai.response_metadata["td3_deduplicated_tool_calls"]), 5)

    def test_real_factory_deduplicates_verified_ioc_calls(self):
        from tests.harness_fixtures import prepare_analysis, session_fixture

        session = session_fixture(self)
        prepare_analysis(session)
        session.enter("ioc")
        messages = [batch(), AIMessage(content="DONE")]
        with (
            patch.object(session, "verify", wraps=session.verify) as verify,
            redirect_stdout(io.StringIO()),
        ):
            result = td3.build_agent(session, FakeModel(messages=iter(messages))).invoke(
                {"messages": [{"role": "user", "content": "test"}]}, config=self.config()
            )
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(result["messages"][-1].content, "DONE")

    def test_distinct_indicators_are_not_removed(self):
        calls = [
            {"name": "verify_ioc", "args": {"value": value}, "id": f"id-{i}", "type": "tool_call"}
            for i, value in enumerate(["203.0.113.42", "192.168.1.100", "192.168.1.101"])
        ]
        original = AIMessage(content="", tool_calls=calls)
        self.assertIs(deduplicate_readonly_calls(original), original)

    def test_delegation_is_not_exposed_by_real_factory(self):
        from tests.harness_fixtures import session_fixture

        session = session_fixture(self)
        session.enter("preuves")
        exposed = []

        class RecordingModel(FakeModel):
            def bind_tools(self, tools, **kwargs):
                exposed.extend(t.name for t in tools)
                return self

        with redirect_stdout(io.StringIO()):
            td3.build_agent(
                session, RecordingModel(messages=iter([AIMessage(content="FIN")]))
            ).invoke({"messages": [{"role": "user", "content": "test"}]}, config=self.config())
        self.assertNotIn("task", exposed)
        self.assertNotIn("execute", exposed)
        self.assertNotIn("write_file", exposed)
        self.assertIn("read_evidence", exposed)

    def test_argument_key_order_does_not_hide_a_duplicate(self):
        message = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "verify_ioc",
                    "args": {"value": "x", "context": "y"},
                    "id": "a",
                    "type": "tool_call",
                },
                {
                    "name": "verify_ioc",
                    "args": {"context": "y", "value": "x"},
                    "id": "b",
                    "type": "tool_call",
                },
            ],
        )
        self.assertEqual(len(deduplicate_readonly_calls(message).tool_calls), 1)

    def test_side_effect_tools_are_never_deduplicated(self):
        for name in [
            "write_file",
            "edit_file",
            "propose_containment",
            "validate_sigma",
            "test_yara",
            "task",
        ]:
            with self.subTest(tool=name):
                message = AIMessage(
                    content="",
                    tool_calls=[
                        {"name": name, "args": {"value": "same"}, "id": str(i), "type": "tool_call"}
                        for i in range(6)
                    ],
                )
                self.assertIs(deduplicate_readonly_calls(message), message)

    def test_containment_keeps_all_human_approval_requests(self):
        @tool
        def propose_containment(action: str) -> str:
            """Synthetic action, never executed before approval."""
            raise AssertionError("Should not be executed before approval")

        message = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "propose_containment",
                    "args": {"action": "synthetic"},
                    "id": str(i),
                    "type": "tool_call",
                }
                for i in range(6)
            ],
        )
        agent = create_deep_agent(
            model=FakeModel(messages=iter([message])),
            tools=[propose_containment],
            middleware=[DeduplicateReadonlyToolCalls()],
            interrupt_on={"propose_containment": {"allowed_decisions": ["approve", "reject"]}},
            checkpointer=InMemorySaver(),
        )
        result = agent.invoke(
            {"messages": [{"role": "user", "content": "synthetic approval test"}]},
            config={**self.config(), "configurable": {"thread_id": "dedup-approval"}},
        )
        self.assertEqual(len(result["__interrupt__"][0].value["action_requests"]), 6)

    def test_repetitions_across_model_responses_still_stop(self):
        messages = [
            batch().model_copy(
                update={
                    "id": f"round-{i}",
                    "tool_calls": [
                        {**call, "id": f"{call['id']}-round-{i}"} for call in FIXTURE["tool_calls"]
                    ],
                }
            )
            for i in range(6)
        ]
        agent = self.make_agent(messages)
        with redirect_stdout(io.StringIO()), self.assertRaises(ExecutionLimitError):
            agent.invoke(
                {"messages": [{"role": "user", "content": "synthetic loop"}]}, config=self.config()
            )
        self.assertEqual(len(self.effects), 3)

    def test_async_execution_also_normalises_the_batch(self):
        agent = self.make_agent([batch(), AIMessage(content="DONE")])
        with redirect_stdout(io.StringIO()):
            result = asyncio.run(
                agent.ainvoke(
                    {"messages": [{"role": "user", "content": "synthetic async test"}]},
                    config=self.config(),
                )
            )
        self.assertEqual(self.effects, ["203.0.113.42"])
        self.assertEqual(result["messages"][-1].content, "DONE")

    def test_first_stop_reason_is_stable_for_parallel_calls(self):
        monitor = ExecutionMonitor(20, repeat_limit=2, progress=quiet)
        monitor.on_tool_start({"name": "verify_ioc"}, '{"value":"same"}')
        for _ in range(4):
            with self.assertRaisesRegex(ExecutionLimitError, "2 fois"):
                monitor.on_tool_start({"name": "verify_ioc"}, '{"value":"same"}')
        self.assertEqual(len(monitor.snapshot()["derniers_outils"]), 2)


if __name__ == "__main__":
    unittest.main()
