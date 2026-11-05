"""Fixtures hors réseau ; aucune exécution des scripts d'incident."""

import shutil
import tempfile
from pathlib import Path

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

from cyber_harness.mitre import MitreReference
from cyber_harness.models import Analysis
from cyber_harness.session import Session

BASE = Path(__file__).resolve().parents[1]
CASE_ROOT = BASE / "examples/inc_2026_0417"
MITRE_FIXTURE = BASE / "tests/fixtures/mitre_minimal.json"
SIGMA = r"""
title: PowerShell Outlook
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\powershell.exe'
    ParentImage|endswith: '\OUTLOOK.EXE'
    CommandLine|contains|all:
      - '-ExecutionPolicy Bypass'
      - '-WindowStyle Hidden'
  condition: sel
"""
YARA = """rule dropper { strings: $a = "'am' + 'siIni' + 'tFa' + 'iled'" $b = "192.168.1.100" condition: all of them }"""


class FakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def call(name, args, i):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{i}"}])


def session_fixture(test):
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    root = Path(directory.name).resolve()
    for name in ("incident", "skills", "benign_samples"):
        shutil.copytree((BASE / "skills" if name == "skills" else CASE_ROOT / name), root / name)
    shutil.copy(CASE_ROOT / "detection_corpus.json", root / "detection_corpus.json")
    reference = MitreReference((MITRE_FIXTURE).read_bytes(), {"fraicheur": "a_jour"})
    return Session(root, root / "output", reference, "synthetic-test")


def analysis_data(s):
    ref = s.evidence.reference("edr_events.jsonl", 2)
    return {
        "constats": [
            {
                "id": "C1",
                "description": "PowerShell lancé par Outlook",
                "statut": "observe",
                "preuves": [ref],
                "horodatage_source": "2024-11-16T08:42:10Z",
                "utc": "2024-11-16T08:42:10Z",
            }
        ],
        "qualifications": {
            "alerte_web": {"conclusion": "Analyse synthétique limitée", "constat_ids": ["C1"]},
            "alerte_poste": {"conclusion": "Lancement observé", "constat_ids": ["C1"]},
        },
        "lien_alertes": "aucun lien prouvé",
        "limites": ["Fixture de test ; pas une analyse SOC réelle"],
    }


def proposal_data(s):
    return {
        "synthese": "Vérifier le maintien de l’isolement",
        "actions": [
            {
                "id": "A1",
                "action": "Vérifier le maintien de l’isolement",
                "cible": "PC-COMPTA-07",
                "constat_ids": ["C1"],
                "preuves": [s.evidence.reference("edr_events.jsonl", 2)],
                "justification": "Lancement suspect",
                "impact_attendu": "Limiter les échanges",
                "risques": "Indisponibilité du poste",
            }
        ],
    }


def protocol_data(s):
    return {
        "proposition_sha256": s.decision["proposition_sha256"],
        "actions": [
            {
                "action_id": "A1",
                "cible": "PC-COMPTA-07",
                "responsable": "Équipe EDR",
                "prerequis": ["Confirmer le poste et son propriétaire"],
                "etapes": ["Consulter le statut du poste dans la console EDR"],
                "verifications": ["Statut isolé et dernière remontée récente"],
                "criteres_arret": ["Identité du poste incertaine"],
                "retour_arriere": [
                    "Toute levée d’isolement nécessite une décision humaine distincte"
                ],
            }
        ],
    }


def factory(stage, s):
    frames = []
    if stage == "preuves":
        for name, lines in s.evidence.content.items():
            for start in range(1, len(lines) + 1, 200):
                frames.append(("read_evidence", {"fichier": name, "debut": start, "limite": 200}))
        frames.append(("save_analysis", {"analysis": analysis_data(s)}))
    elif stage == "ioc":
        value = "PC-COMPTA-07"
        frames = [
            ("verify_ioc", {"value": value}),
            (
                "save_iocs",
                {
                    "iocs": [
                        {
                            "type": "autre",
                            "valeur": value,
                            "references": s.evidence.occurrences(value),
                            "contexte": "Poste concerné, identifiant interne",
                            "confiance": "haute",
                            "constat_ids": ["C1"],
                        }
                    ]
                },
            ),
        ]
    elif stage == "mitre":
        frames = [
            ("check_mitre", {"technique_id": "T1059.001"}),
            (
                "save_mitre",
                {
                    "associations": [
                        {
                            "id": "T1059.001",
                            "constat_ids": ["C1"],
                            "justification": "Lancement PowerShell observé",
                        }
                    ]
                },
            ),
        ]
    elif stage == "regles":
        frames = [("validate_sigma", {"rule_yaml": SIGMA}), ("test_yara", {"rule_text": YARA})]
    elif stage == "confinement":
        frames = [("propose_containment", {"proposal": proposal_data(s)})]
    elif stage == "protocole":
        frames = [("save_protocol", {"protocol": protocol_data(s)})]
    elif stage == "rapport":
        frames = [
            (
                "save_report_summary",
                {"summary": {"resume": "PowerShell lancé par Outlook.", "constat_ids": ["C1"]}},
            )
        ]
    return FakeModel(
        messages=iter(
            [call(name, args, n) for n, (name, args) in enumerate(frames)]
            + [AIMessage(content="FIN")]
        )
    )


def prepare_analysis(s):
    s.enter("preuves")
    for name, lines in s.evidence.content.items():
        for start in range(1, len(lines) + 1, 200):
            s.evidence.page(name, start, 200)
    s.save_analysis(Analysis.model_validate(analysis_data(s)))
