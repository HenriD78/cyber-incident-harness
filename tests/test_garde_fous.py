"""Tests des limites réelles du harness, sans réseau ni fichiers de production."""

import unittest

from cyber_harness.models import Proposal
from cyber_harness.tools import test_yara as yara_tool
from cyber_harness.tools import validate_sigma
from cyber_harness.workflow import build_agent
from tests.harness_fixtures import (
    AIMessage,
    FakeModel,
    call,
    prepare_analysis,
    proposal_data,
    session_fixture,
)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.s = session_fixture(self)

    def test_evidence_reference_and_secrets_unreachable_via_filesystem(self):
        self.s.enter("preuves")
        script = [
            call("read_file", {"file_path": p}, n)
            for n, p in enumerate(
                ["/incident/app.log", "/data/enterprise-attack.json", "/.env", "/../prompts.py"]
            )
        ]
        script += [AIMessage(content="FIN")]
        result = build_agent(self.s, FakeModel(messages=iter(script))).invoke(
            {"messages": [{"role": "user", "content": "test"}]}
        )
        messages = [str(m.content).lower() for m in result["messages"] if m.type == "tool"]
        self.assertTrue(all("error" in m or "not found" in m for m in messages), messages)
        self.assertTrue(self.s.evidence.intact())

    def test_rule_tools_reject_protected_destinations(self):
        for filename in (
            "containment.json",
            "audit.jsonl",
            "../incident/app.log",
            "tests/sigma-1.json",
        ):
            self.assertIn(
                "refusée", validate_sigma.invoke({"rule_yaml": "x", "filename": filename})
            )
            self.assertIn("refusée", yara_tool.invoke({"rule_text": "x", "filename": filename}))

    def test_proposal_is_not_a_human_approval(self):
        prepare_analysis(self.s)
        self.s.enter("confinement")
        self.s.propose(Proposal.model_validate(proposal_data(self.s)))
        self.assertFalse((self.s.output / "containment.json").exists())
        with self.assertRaises(ValueError):
            self.s.enter("protocole")
        self.s.decide(False, "Refus humain")
        with self.assertRaises(ValueError):
            self.s.propose(Proposal.model_validate(proposal_data(self.s)))
        self.assertIsNone(self.s.protocol)


if __name__ == "__main__":
    unittest.main()
