"""Vérifier et mettre à jour atomiquement le référentiel MITRE officiel."""

import json

from cyber_harness.config import MITRE_FILE
from cyber_harness.mitre import refresh_reference

if __name__ == "__main__":
    reference = refresh_reference(MITRE_FILE)
    print(json.dumps(reference.metadata, ensure_ascii=False, indent=2))
    raise SystemExit(0 if reference.metadata.get("fraicheur") == "a_jour" else 1)
