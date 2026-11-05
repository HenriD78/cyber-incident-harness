"""Régressions avec modèles scriptés et dossiers temporaires, sans Ollama."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from deepagents import create_deep_agent
from langchain.agents.middleware import ModelCallLimitMiddleware
from langchain.agents.middleware.model_call_limit import ModelCallLimitExceededError
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

import cyber_harness.workflow as td3
from cyber_harness.runtime.control import ExecutionLimitError, ExecutionMonitor, graph_step_limit


class FakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def call(name, args, index):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"call-{index}"}])


def quiet(*args, **kwargs):
    pass


class ExecutionTests(unittest.TestCase):
    def make_agent(self, script, limit):
        self.effects = []

        @tool
        def echo_value(value: int) -> str:
            """Return an integer as text, with no external side effect."""
            self.effects.append(value)
            return str(value)

        return create_deep_agent(
            model=FakeModel(messages=iter(script)),
            tools=[echo_value],
            middleware=[
                ModelCallLimitMiddleware(run_limit=limit, thread_limit=limit, exit_behavior="error")
            ],
            checkpointer=InMemorySaver(),
        )

    def test_budget_is_reached_before_graph_recursion_limit(self):
        script = [call("echo_value", {"value": i}, i) for i in range(10)]
        agent = self.make_agent(script, limit=3)
        monitor = ExecutionMonitor(3, progress=quiet)
        with self.assertRaises((ExecutionLimitError, ModelCallLimitExceededError)):
            agent.invoke(
                {"messages": [{"role": "user", "content": "synthetic test"}]},
                config={
                    "callbacks": [monitor],
                    "configurable": {"thread_id": "budget"},
                    "recursion_limit": graph_step_limit(3),
                },
            )
        self.assertEqual(monitor.model_calls, 3)
        self.assertEqual(self.effects, [0, 1, 2])

    def test_repeated_tool_is_blocked_before_another_execution(self):
        script = [call("echo_value", {"value": 7}, i) for i in range(10)]
        agent = self.make_agent(script, limit=10)
        monitor = ExecutionMonitor(10, repeat_limit=3, progress=quiet)
        with self.assertRaisesRegex(ExecutionLimitError, "Boucle détectée"):
            agent.invoke(
                {"messages": [{"role": "user", "content": "synthetic test"}]},
                config={
                    "callbacks": [monitor],
                    "configurable": {"thread_id": "repeat"},
                    "recursion_limit": graph_step_limit(10),
                },
            )
        self.assertEqual(self.effects, [7, 7])
        self.assertEqual(monitor.snapshot()["derniers_outils"][-1]["outil"], "echo_value")

    def test_subagent_calls_share_the_same_global_budget(self):
        script = [
            call("task", {"description": "synthetic test", "subagent_type": "general-purpose"}, 0)
        ]
        script += [call("echo_value", {"value": i}, i + 1) for i in range(10)]
        agent = self.make_agent(script, limit=20)
        monitor = ExecutionMonitor(3, progress=quiet)
        with self.assertRaises(ExecutionLimitError):
            agent.invoke(
                {"messages": [{"role": "user", "content": "synthetic delegation"}]},
                config={
                    "callbacks": [monitor],
                    "configurable": {"thread_id": "delegation"},
                    "recursion_limit": graph_step_limit(20),
                },
            )
        self.assertEqual(monitor.model_calls, 3)
        self.assertEqual(self.effects, [0, 1])

    def test_budget_is_not_reset_after_human_approval(self):
        # Une interruption LangGraph explicite simule une reprise humaine.
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import interrupt

        model = FakeModel(messages=iter([AIMessage(content="before"), AIMessage(content="after")]))

        def first(state, config):
            model.invoke("synthetic first call", config=config)
            return {}

        def approval(state):
            interrupt("approve synthetic step")
            return {}

        def last(state, config):
            model.invoke("synthetic second call", config=config)
            return {}

        builder = StateGraph(dict)
        builder.add_node("first", first)
        builder.add_node("approval", approval)
        builder.add_node("last", last)
        builder.add_edge(START, "first")
        builder.add_edge("first", "approval")
        builder.add_edge("approval", "last")
        builder.add_edge("last", END)
        graph = builder.compile(checkpointer=InMemorySaver())
        monitor = ExecutionMonitor(1, progress=quiet)
        config = {"callbacks": [monitor], "configurable": {"thread_id": "approval"}}
        first_result = graph.invoke({}, config=config)
        self.assertIn("__interrupt__", first_result)
        with self.assertRaises(ExecutionLimitError):
            graph.invoke(Command(resume=True), config=config)
        self.assertEqual(monitor.model_calls, 1)

    def test_full_80_call_budget_is_not_preempted_by_graph_steps(self):
        script = [call("echo_value", {"value": i}, i) for i in range(90)]
        agent = self.make_agent(script, limit=80)
        monitor = ExecutionMonitor(80, progress=quiet)
        with self.assertRaises((ExecutionLimitError, ModelCallLimitExceededError)):
            agent.invoke(
                {"messages": [{"role": "user", "content": "synthetic long loop"}]},
                config={
                    "callbacks": [monitor],
                    "configurable": {"thread_id": "full-budget"},
                    "recursion_limit": graph_step_limit(80),
                },
            )
        self.assertEqual(monitor.model_calls, 80)
        self.assertEqual(len(self.effects), 80)

    def test_repetition_resets_when_arguments_change(self):
        monitor = ExecutionMonitor(10, repeat_limit=3, progress=quiet)
        for value in [1, 1, 2, 1, 1]:
            monitor.on_tool_start({"name": "read"}, json.dumps({"value": value}))
        self.assertEqual(len(monitor.snapshot()["derniers_outils"]), 5)

    def test_write_file_repetitions_are_bounded(self):
        script = [
            call("write_file", {"file_path": "/output/test.txt", "content": "synthetic"}, i)
            for i in range(6)
        ]
        agent = self.make_agent(script, limit=10)
        monitor = ExecutionMonitor(10, repeat_limit=3, progress=quiet)
        with self.assertRaisesRegex(ExecutionLimitError, "Boucle détectée"):
            agent.invoke(
                {"messages": [{"role": "user", "content": "test"}]},
                config={"callbacks": [monitor], "configurable": {"thread_id": "writes"}},
            )
        self.assertEqual(len(monitor.snapshot()["derniers_outils"]), 3)

    def test_other_tools_keep_the_repetition_limit(self):
        for name in [
            "read_file",
            "edit_file",
            "verify_ioc",
            "propose_containment",
            "validate_sigma",
            "test_yara",
        ]:
            with self.subTest(tool=name):
                monitor = ExecutionMonitor(10, repeat_limit=3, progress=quiet)
                monitor.on_tool_start({"name": name}, '{"value":"same"}')
                monitor.on_tool_start({"name": name}, '{"value":"same"}')
                with self.assertRaisesRegex(ExecutionLimitError, "Boucle détectée"):
                    monitor.on_tool_start({"name": name}, '{"value":"same"}')


class MainTests(unittest.TestCase):
    def test_stops_save_report_diagnostic_and_check_integrity(self):
        from tests.harness_fixtures import session_fixture

        for failure, expected_code in [
            (GraphRecursionError("synthetic graph limit"), 1),
            (ExecutionLimitError("synthetic repeated tool"), 1),
            (KeyboardInterrupt(), 130),
        ]:
            with self.subTest(failure=type(failure).__name__):
                session = session_fixture(self)

                class FailingAgent:
                    def invoke(self, *args, **kwargs):
                        raise failure

                with (
                    patch.object(td3, "build_agent", return_value=FailingAgent()),
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(td3.run_workflow(session), expected_code)
                diagnostic = json.loads((session.output / "diagnostic_execution.json").read_text())
                self.assertEqual(diagnostic["statut"], "incomplet")
                self.assertTrue(diagnostic["preuves_intactes"])
                self.assertTrue((session.output / "rapport_incident.md").exists())


if __name__ == "__main__":
    unittest.main()
