"""Point d'entrée : configuration, répertoire de sortie et lancement du workflow."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from uuid import uuid4

from cyber_harness.config import (
    CASE_ROOT,
    MITRE_FILE,
    OUTPUT_DIR,
    PROJECT_ROOT,
    SKILLS_DIR,
    RunSettings,
)
from cyber_harness.evidence import atomic_write, safe_path
from cyber_harness.mitre import refresh_reference
from cyber_harness.session import Session
from cyber_harness.workflow import run_workflow


def validate_output_path(output: Path, case: Path, skills: Path, reference: Path) -> None:
    """Refuser de déplacer ou d'écraser les sources, preuves et résultats historiques."""
    safe_path(output.parent, output.name)
    output = output.resolve()
    protected = [
        case,
        skills,
        *(
            PROJECT_ROOT / name
            for name in (
                "src",
                "tests",
                "docs",
                "results",
                "examples",
                "skills",
                "scripts",
                "data",
                ".github",
            )
        ),
    ]
    for path in protected:
        path = path.resolve()
        if output.is_relative_to(path) or path.is_relative_to(output):
            raise ValueError(f"Sortie en conflit avec un répertoire protégé : {path}")
    if reference.resolve().is_relative_to(output):
        raise ValueError("Le référentiel MITRE ne peut pas appartenir à la sortie")
    if output == output.parent / "runs":
        raise ValueError("Le nom runs est réservé aux archives des nouvelles exécutions")
    if output.exists() and not output.is_dir():
        raise ValueError("La sortie doit désigner un répertoire")


def archive_previous_output(output: Path) -> None:
    """Archiver uniquement la sortie de travail, jamais les résultats de l'évaluation."""
    safe_path(output.parent, output.name)
    if output.exists() and any(output.iterdir()):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-")
        target = safe_path(output.parent, "runs/" + stamp + uuid4().hex[:8])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(output), str(target))
        print(f"[i] Sortie précédente archivée : {target}")
    output.mkdir(parents=True, exist_ok=True)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyser un incident à partir de preuves statiques."
    )
    parser.add_argument(
        "--case-dir",
        type=Path,
        default=CASE_ROOT,
        help="dossier contenant incident/, benign_samples/ et detection_corpus.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
        help="sortie de travail (par défaut : artifacts/latest/)",
    )
    parser.add_argument(
        "--skills-dir", type=Path, default=SKILLS_DIR, help="procédures en lecture seule"
    )
    parser.add_argument(
        "--mitre-file", type=Path, default=MITRE_FILE, help="cache local du référentiel officiel"
    )
    parser.add_argument("--model", default=os.getenv("TD3_MODEL", "gemma4:31b-cloud"))
    parser.add_argument("--run-limit", type=int, default=os.getenv("TD3_RUN_LIMIT", "200"))
    parser.add_argument("--repeat-limit", type=int, default=os.getenv("TD3_REPEAT_LIMIT", "4"))
    parser.add_argument(
        "--run-label",
        "--version",
        dest="run_label",
        default="harness",
        help="étiquette des traces, indépendante des versions historiques",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = argument_parser()
    args = parser.parse_args(argv)
    case, output, skills, reference_file = (
        path.absolute()
        for path in (args.case_dir, args.output_dir, args.skills_dir, args.mitre_file)
    )
    try:
        settings = RunSettings(args.model, args.run_limit, args.repeat_limit)
        if not case.is_dir() or not skills.is_dir():
            raise ValueError(
                "Dossier de cas ou de procédures absent ; vérifier --case-dir et --skills-dir"
            )
        validate_output_path(output, case, skills, reference_file)
        archive_previous_output(output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    # Le réseau MITRE appartient à l'hôte ; aucune URL n'est fournie par le modèle.
    try:
        reference = refresh_reference(reference_file)
    except (OSError, ValueError) as exc:
        print(f"[!] MITRE indisponible : {exc}")
        reference = None
    thread_id = f"td3-{args.run_label}-{uuid4()}"
    try:
        session = Session(case, output, reference, thread_id, skills_dir=skills, settings=settings)
    except (OSError, ValueError, KeyError) as exc:
        error = f"Initialisation impossible : {type(exc).__name__}: {exc}"
        atomic_write(
            output,
            "diagnostic_execution.json",
            json.dumps(
                {
                    "statut": "incomplet",
                    "erreur": error,
                    "thread_id": thread_id,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
        atomic_write(
            output,
            "rapport_incident.md",
            "# Rapport d'incident — INCOMPLET\n\n"
            + error
            + "\n\nAucune analyse validée, aucune décision de confinement, aucune action exécutée.\n",
        )
        print(f"[!] {error}")
        return 1
    session.audit.event(
        "configuration",
        {
            "modele": settings.model,
            "budget": settings.run_limit,
            "versions": {
                name: version(name)
                for name in (
                    "deepagents",
                    "langchain",
                    "langchain-ollama",
                    "pysigma",
                    "yara-python",
                )
            },
        },
    )
    print(
        f"[i] Modèle : {settings.model} | thread : {thread_id} | journal local : {output / 'audit.jsonl'}"
    )
    return run_workflow(session)
