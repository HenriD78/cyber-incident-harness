"""Tests hors réseau : python tests/test_export_trace.py."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from langsmith.schemas import Run
from langsmith.types.run import Run as QueryRun
from langsmith.utils import LangSmithAuthError

from scripts import exporter_trace as exporter

START = datetime(2026, 11, 4, tzinfo=timezone.utc)


def make_run(kind="chain", *, root=None, parent=None, offset=0, **kwargs):
    rid = uuid4()
    return Run(
        id=rid,
        name=f"test-{kind}",
        run_type=kind,
        trace_id=root or rid,
        parent_run_id=parent,
        start_time=START + timedelta(seconds=offset),
        end_time=START + timedelta(seconds=offset + 1),
        **kwargs,
    )


class FakeClient:
    api_key = "secret-used-only-in-test"
    workspace_id = None
    api_url = "https://eu.api.smith.langchain.com"

    def __init__(self, seeds, runs):
        self.seeds = seeds
        self.runs = runs
        self.queries = []

    def list_runs(self, **query):
        self.queries.append(query)
        if "trace_id" in query:
            return (run for run in self.runs if str(run.trace_id) == str(query["trace_id"]))
        return iter(self.seeds)

    def close(self):
        pass


class ExportTests(unittest.TestCase):
    def test_run_selection_fetches_whole_trace_and_deduplicates(self):
        root = make_run()
        llm = make_run("llm", root=root.id, parent=root.id, offset=1)
        tool = make_run("tool", root=root.id, parent=root.id, offset=2)
        # Un ID d'appel enfant doit aussi récupérer la racine et les autres enfants.
        client = FakeClient([llm], [tool, root, llm])
        result = exporter.collect_runs(client, "project", run_id=llm.id)
        self.assertEqual([run.id for run in result], [root.id, llm.id, tool.id])
        self.assertEqual(client.queries[0]["run_ids"], [llm.id])
        self.assertNotIn("limit", client.queries[1])

    def test_thread_selection_includes_human_resumptions(self):
        first, resumed = make_run(), make_run(offset=5)
        llm = make_run("llm", root=resumed.id, parent=resumed.id, offset=6)
        client = FakeClient([first, resumed], [first, resumed, llm])
        thread = 'thread-"quoted"'
        result = exporter.collect_runs(client, "project", thread_id=thread)
        self.assertEqual(len(result), 3)
        self.assertIn(json.dumps(thread), client.queries[0]["filter"])
        self.assertEqual(len(client.queries), 3)
        self.assertNotIn("limit", client.queries[0])

    def test_empty_selection_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "Aucune exécution"):
            exporter.collect_runs(FakeClient([], []), "project", run_id=uuid4())

    def test_payload_retains_messages_and_counts_only_llm_tokens(self):
        root = make_run(total_tokens=999)
        llm = make_run(
            "llm",
            root=root.id,
            parent=root.id,
            inputs={"messages": [{"role": "user", "content": "question"}]},
            outputs={"generations": [{"message": {"content": "answer"}}]},
            total_tokens=5,
            prompt_tokens=3,
            completion_tokens=2,
        )
        missing_usage = make_run("llm", root=root.id, parent=root.id)
        result = exporter.build_export([root, llm, missing_usage], project="project")
        self.assertEqual(result["summary"]["reported_llm_tokens"], 5)
        self.assertEqual(result["summary"]["llm_calls_without_token_count"], 1)
        self.assertEqual(result["llm_calls"][0]["inputs"], llm.inputs)
        self.assertEqual(result["llm_calls"][0]["outputs"], llm.outputs)
        self.assertEqual(result["llm_calls"][0]["duration_seconds"], 1)
        self.assertEqual(result["llm_calls"][0]["parent_run_id"], str(root.id))
        self.assertNotIn("attachments", result["runs"][0])

    def test_credentials_are_redacted_recursively(self):
        llm = make_run(
            "llm",
            inputs={"messages": [f"token={FakeClient.api_key}"], "API_KEY": "other-key"},
            outputs={"nested": [{"Authorization": "Bearer other-key"}]},
        )
        result = exporter.build_export([llm], project="project", api_key=FakeClient.api_key)
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(FakeClient.api_key, encoded)
        self.assertNotIn("other-key", encoded)
        self.assertIn("[MASQUÉ]", encoded)

    def test_partial_trace_is_identifiable(self):
        parent = uuid4()
        run = make_run("llm", parent=parent, error="interrupted")
        run.end_time = None
        result = exporter.build_export([run], project="project")
        self.assertEqual(result["summary"]["missing_parent_ids"], [str(parent)])
        self.assertEqual(result["summary"]["unfinished_runs"], 1)
        self.assertEqual(result["summary"]["errors"], 1)
        self.assertIsNone(result["llm_calls"][0]["duration_seconds"])

    def test_existing_export_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            exporter.write_export(path, {"original": True})
            with self.assertRaises(FileExistsError):
                exporter.write_export(path, {"replacement": True})
            self.assertEqual(json.loads(path.read_text()), {"original": True})

    def test_cli_exports_using_existing_client_without_agent(self):
        root = make_run()
        llm = make_run("llm", root=root.id, parent=root.id)
        client = FakeClient([root], [root, llm])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            with (
                patch.object(exporter, "Client", return_value=client),
                patch.object(exporter, "TraceReader", return_value=client),
                redirect_stdout(io.StringIO()),
            ):
                code = exporter.main(["--run-id", str(root.id), "--output", str(path)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(path.read_text())["summary"]["llm_calls"], 1)

    def test_cli_list_shows_identifiers_without_prompt_contents(self):
        root = make_run(
            inputs={"messages": ["private prompt"]},
            extra={"metadata": {"thread_id": "td3-v2-example"}},
        )
        client = FakeClient([root], [root])
        with (
            patch.object(exporter, "Client", return_value=client),
            patch.object(exporter, "TraceReader", return_value=client),
            redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(
                exporter.main(["--list", "--project", "selected-project", "--limit", "5"]), 0
            )
        self.assertIn(str(root.id), out.getvalue())
        self.assertIn("td3-v2-example", out.getvalue())
        self.assertNotIn("private prompt", out.getvalue())
        self.assertEqual(client.queries[0]["project_name"], "selected-project")
        self.assertEqual(client.queries[0]["limit"], 5)

    def test_invalid_workspace_fails_before_querying(self):
        client = FakeClient([], [])
        client.workspace_id = "YOUR_WORKSPACE_ID"
        with (
            patch.object(exporter, "Client", return_value=client),
            patch.object(exporter, "TraceReader", return_value=client),
            redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(exporter.main(["--list"]), 1)
        self.assertIn("Workspace invalide", err.getvalue())
        self.assertEqual(client.queries, [])

    def test_authentication_error_does_not_print_api_key(self):
        client = FakeClient([], [])
        client.list_runs = lambda **kw: (_ for _ in ()).throw(
            LangSmithAuthError(FakeClient.api_key)
        )
        with (
            patch.object(exporter, "Client", return_value=client),
            patch.object(exporter, "TraceReader", return_value=client),
            redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(exporter.main(["--list"]), 1)
        self.assertNotIn(FakeClient.api_key, err.getvalue())
        self.assertIn("https://eu.api.smith.langchain.com", err.getvalue())


class ReaderTests(unittest.TestCase):
    def test_v2_query_keeps_history_fields_parentage_and_pagination(self):
        root_id, child_id, project_id = str(uuid4()), str(uuid4()), str(uuid4())
        root = QueryRun(
            id=root_id,
            trace_id=root_id,
            run_type="CHAIN",
            name="root",
            start_time=START,
            end_time=START + timedelta(seconds=5),
            parent_run_ids=[],
            project_id=project_id,
            extra={"metadata": {"modele": "test"}},
            metadata={"thread_id": "thread"},
        )
        child = QueryRun(
            id=child_id,
            trace_id=root_id,
            run_type="LLM",
            name="model",
            start_time=START,
            end_time=START + timedelta(seconds=1),
            parent_run_ids=[root_id],
            project_id=project_id,
            inputs={"messages": ["question"]},
            outputs={"content": "answer"},
            total_tokens=7,
        )
        queries = []

        def query_v2(**kwargs):
            queries.append(kwargs)
            # Itérateur paginé : chaque élément doit être consommé pour un export.
            yield root
            yield child

        client = FakeClient([], [])
        client.read_project = lambda **kw: SimpleNamespace(id=project_id)
        api = SimpleNamespace(runs=SimpleNamespace(query_v2=query_v2))
        reader = exporter.TraceReader(client, api=api)
        result = list(reader.list_runs(project_name="project", trace_id=root_id))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1].parent_run_id, result[0].id)
        self.assertEqual(result[1].run_type, "llm")
        self.assertEqual(result[1].inputs, child.inputs)
        self.assertEqual(result[1].outputs, child.outputs)
        self.assertEqual(result[0].metadata, {"modele": "test", "thread_id": "thread"})
        self.assertEqual(queries[0]["project_ids"], [project_id])
        self.assertEqual(queries[0]["min_start_time"].year, 1970)
        self.assertIn("INPUTS", queries[0]["selects"])
        self.assertIn("OUTPUTS", queries[0]["selects"])
        self.assertFalse(queries[0]["include_subtree_usage"])

        listed = list(reader.list_runs(project_name="project", is_root=True, limit=1))
        self.assertEqual(len(listed), 1)
        self.assertEqual(queries[-1]["page_size"], 1)

    def test_v2_id_filter_uses_strings_and_query_alias(self):
        queries = []
        client = FakeClient([], [])
        client.read_project = lambda **kw: SimpleNamespace(id=uuid4())
        api = SimpleNamespace(
            runs=SimpleNamespace(query=lambda **kw: queries.append(kw) or iter([]))
        )
        reader = exporter.TraceReader(client, api=api)
        run_id = uuid4()
        list(reader.list_runs(project_name="project", run_ids=[run_id], limit=1))
        self.assertEqual(queries[0]["ids"], [str(run_id)])


if __name__ == "__main__":
    unittest.main()
