"""Outils autonomes pour vérifier des IOC, dates, techniques et détections.

Le workflow utilise les outils fermés sur Session ; ces wrappers servent aux
vérifications unitaires sur le cas pédagogique. Ils écrivent dans artifacts/latest/.
"""

from __future__ import annotations

import binascii
import json
from datetime import datetime, timezone
from functools import lru_cache

from langchain.tools import tool

from cyber_harness.config import CASE_ROOT, MITRE_FILE, OUTPUT_DIR
from cyber_harness.detection import evaluate_sigma as evaluate_sigma
from cyber_harness.detection import evaluate_yara as evaluate_yara
from cyber_harness.evidence import EvidenceStore, atomic_write, decode_static, read_bytes
from cyber_harness.mitre import MitreReference

INCIDENT = CASE_ROOT / "incident"
BENIGN = CASE_ROOT / "benign_samples"
OUTPUT = OUTPUT_DIR


@tool
def verify_ioc(value: str) -> str:
    """Vérifier la valeur complète dans les preuves ; renvoyer références et empreintes."""
    refs = EvidenceStore(INCIDENT).occurrences(value)
    return json.dumps(
        {
            "valeur": value,
            "references": refs,
            "resultat": ", ".join(f"{r['fichier']}:{r['ligne']}" for r in refs)
            if refs
            else "introuvable dans les preuves",
        },
        ensure_ascii=False,
    )


@tool
def decode_powershell_b64(encoded: str) -> str:
    """Décoder statiquement PowerShell UTF-16LE/UTF-8, sans jamais l'exécuter.
    Le harness lie ce résultat à une ligne source via decode_evidence."""
    try:
        return json.dumps(decode_static(encoded), ensure_ascii=False)
    except (ValueError, binascii.Error) as exc:
        return f"Base64 invalide : {exc}"


# ---------------------------------------------------------------------------
# 3. Convertir un horodatage de log en UTC
# ---------------------------------------------------------------------------
_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",  # Apache : 15/Nov/2024:22:18:15 +0100
    "%Y-%m-%dT%H:%M:%S%z",  # ISO 8601 : 2024-11-15T21:18:22Z ou +01:00
    "%Y-%m-%d %H:%M:%S%z",
]


@tool
def to_utc(timestamp: str) -> str:
    """Convertit un horodatage de log en UTC (ISO 8601, suffixe Z).
    Formats acceptés : Apache '15/Nov/2024:22:18:15 +0100', ISO '2024-11-15T21:18:22Z'
    ou avec décalage '+01:00'. Refuse un horodatage sans fuseau plutôt que de deviner."""
    ts = timestamp.strip().strip("[]")
    ts_iso = ts.replace("Z", "+0000")
    for fmt in _FORMATS:
        try:
            dt = datetime.strptime(ts_iso, fmt)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return (
        f"format non reconnu ou fuseau absent : '{timestamp}'. "
        "Indiquez le fuseau (ex. +0100 ou Z) au lieu de le supposer."
    )


# ---------------------------------------------------------------------------
# 4. Contrôler un ID MITRE ATT&CK dans le référentiel officiel
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _mitre_index() -> tuple[dict, str]:
    reference = MitreReference(read_bytes(MITRE_FILE.parent, MITRE_FILE.name, 100_000_000))
    return reference.index, reference.version


@tool
def check_mitre(technique_id: str) -> str:
    """Vérifier une technique officielle et signaler les techniques révoquées/obsolètes."""
    index, version = _mitre_index()
    entry = index.get(technique_id.strip().upper())
    if entry is None:
        return f"{technique_id} : identifiant inexistant dans ATT&CK {version}"
    result = dict(entry)
    if entry["revoquee"] or entry["obsolete"]:
        result["avertissement"] = "Technique révoquée/obsolète : vérifier le remplaçant"
    return json.dumps(result, ensure_ascii=False)


def load_corpus() -> dict:
    return json.loads(read_bytes(CASE_ROOT, "detection_corpus.json"))


@tool
def validate_sigma(rule_yaml: str, filename: str = "regle_sigma.yml") -> str:
    """Tester Sigma sur le corpus annoté. Destination fixe regle_sigma.yml uniquement."""
    if filename != "regle_sigma.yml":
        return "Destination refusée : regle_sigma.yml uniquement"
    result = evaluate_sigma(rule_yaml, INCIDENT, load_corpus()["sigma"])
    atomic_write(OUTPUT, filename, rule_yaml)
    return json.dumps(result, ensure_ascii=False)


@tool
def test_yara(rule_text: str, filename: str = "regle_yara.yar") -> str:
    """Tester statiquement YARA en processus borné, inclusions interdites, destination fixe."""
    if filename != "regle_yara.yar":
        return "Destination refusée : regle_yara.yar uniquement"
    result = evaluate_yara(rule_text, INCIDENT, BENIGN, load_corpus()["yara"])
    atomic_write(OUTPUT, filename, rule_text)
    return json.dumps(result, ensure_ascii=False)


ALL_TOOLS = [verify_ioc, decode_powershell_b64, to_utc, check_mitre, validate_sigma, test_yara]
