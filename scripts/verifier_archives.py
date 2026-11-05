"""Vérifier les empreintes des résultats historiques, sans les modifier."""

from __future__ import annotations

import hashlib
import json

from cyber_harness.config import PROJECT_ROOT
from cyber_harness.evidence import safe_path


def main() -> int:
    root = PROJECT_ROOT / "results"
    manifest = json.loads((root / "manifest_integrite.json").read_text(encoding="utf-8"))
    errors = []
    for name, expected in manifest["fichiers"].items():
        try:
            actual = hashlib.sha256(safe_path(root, name).read_bytes()).hexdigest()
            if actual != expected:
                errors.append(f"Contenu modifié : {name}")
        except (OSError, ValueError) as exc:
            errors.append(f"Fichier inaccessible : {name} ({type(exc).__name__})")
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"{len(manifest['fichiers'])} fichiers historiques vérifiés : contenus intacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
