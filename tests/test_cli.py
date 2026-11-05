"""Régressions du lancement : chemins protégés, configuration et clôture locale."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cyber_harness import cli
from cyber_harness.config import OUTPUT_DIR, PROJECT_ROOT
from tests.harness_fixtures import session_fixture


class CliTests(unittest.TestCase):
    def setUp(self):
        self.session = session_fixture(self)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name).resolve() / "output"

    def arguments(self):
        return [
            "--case-dir",
            str(self.session.base),
            "--skills-dir",
            str(self.session.skills_dir),
            "--output-dir",
            str(self.output),
            "--model",
            "synthetic-test-model",
            "--run-limit",
            "17",
            "--repeat-limit",
            "3",
        ]

    def test_default_output_is_separate_from_historical_results(self):
        self.assertEqual(OUTPUT_DIR, PROJECT_ROOT / "artifacts/latest")
        self.assertFalse(OUTPUT_DIR.is_relative_to(PROJECT_ROOT / "results"))

    def test_historical_source_and_parent_directories_are_protected(self):
        for output in (
            PROJECT_ROOT,
            PROJECT_ROOT / "results/v5_validation_humaine",
            PROJECT_ROOT / "src/generated",
            PROJECT_ROOT / "artifacts/../results/v1_prototype",
            self.session.base,
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                cli.validate_output_path(
                    output,
                    self.session.base,
                    self.session.skills_dir,
                    PROJECT_ROOT / "data/enterprise-attack.json",
                )

    def test_protected_output_is_rejected_before_network_or_archiving(self):
        args = self.arguments()
        args[args.index("--output-dir") + 1] = str(PROJECT_ROOT / "results/v1_prototype")
        with (
            patch.object(cli, "refresh_reference") as refresh,
            patch.object(cli, "archive_previous_output") as archive,
        ):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                cli.main(args)
        self.assertEqual(error.exception.code, 2)
        refresh.assert_not_called()
        archive.assert_not_called()

    def test_invalid_budget_is_rejected_before_creating_output(self):
        args = self.arguments()
        args[args.index("--run-limit") + 1] = "0"
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            cli.main(args)
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_archive_preserves_previous_output_and_creates_empty_working_directory(self):
        self.output.mkdir()
        content = b"historical bytes\n"
        (self.output / "audit.jsonl").write_bytes(content)
        with redirect_stdout(io.StringIO()):
            cli.archive_previous_output(self.output)
        archives = list((self.output.parent / "runs").iterdir())
        self.assertEqual(len(archives), 1)
        self.assertEqual((archives[0] / "audit.jsonl").read_bytes(), content)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_cli_passes_explicit_configuration_to_workflow(self):
        with (
            patch.object(cli, "refresh_reference", return_value=self.session.reference),
            patch.object(cli, "run_workflow", return_value=0) as workflow,
        ):
            with redirect_stdout(io.StringIO()):
                code = cli.main(self.arguments())
        launched = workflow.call_args.args[0]
        self.assertEqual(code, 0)
        self.assertEqual(launched.settings.model, "synthetic-test-model")
        self.assertEqual(launched.settings.run_limit, 17)
        self.assertEqual(launched.settings.repeat_limit, 3)
        self.assertEqual(launched.skills_dir, self.session.skills_dir)
        self.assertEqual(launched.output, self.output)
        self.assertIsNone(launched.decision)

    def test_invalid_case_keeps_an_explicit_partial_report(self):
        (self.session.base / "detection_corpus.json").write_text("invalid json")
        with (
            patch.object(cli, "refresh_reference", return_value=self.session.reference),
            patch.object(cli, "run_workflow") as workflow,
        ):
            with redirect_stdout(io.StringIO()):
                code = cli.main(self.arguments())
        self.assertEqual(code, 1)
        workflow.assert_not_called()
        diagnostic = json.loads((self.output / "diagnostic_execution.json").read_text())
        self.assertEqual(diagnostic["statut"], "incomplet")
        self.assertIn("aucune action exécutée", (self.output / "rapport_incident.md").read_text())

    def test_importing_baseline_does_not_create_an_agent(self):
        import importlib

        with patch("deepagents.create_deep_agent") as create:
            importlib.import_module("examples.agent_baseline")
        create.assert_not_called()
