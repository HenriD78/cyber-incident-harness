"""Chemins du dépôt et configuration explicite d'une exécution."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASE_ROOT = PROJECT_ROOT / "examples" / "inc_2026_0417"
SKILLS_DIR = PROJECT_ROOT / "skills"
MITRE_FILE = PROJECT_ROOT / "data" / "enterprise-attack.json"
OUTPUT_DIR = PROJECT_ROOT / "artifacts" / "latest"


@dataclass(frozen=True)
class RunSettings:
    """Paramètres partagés par toutes les phases d'un même run."""

    model: str = "gemma4:31b-cloud"
    run_limit: int = 200
    repeat_limit: int = 4

    def __post_init__(self):
        if not self.model.strip():
            raise ValueError("Un nom de modèle est requis")
        if self.run_limit < 1 or self.repeat_limit < 2:
            raise ValueError("Budget LLM >= 1 et limite de répétition >= 2 requis")

    @classmethod
    def from_environment(cls) -> RunSettings:
        return cls(
            model=os.getenv("TD3_MODEL", "gemma4:31b-cloud"),
            run_limit=int(os.getenv("TD3_RUN_LIMIT", "200")),
            repeat_limit=int(os.getenv("TD3_REPEAT_LIMIT", "4")),
        )
