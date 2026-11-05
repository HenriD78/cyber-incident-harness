"""Compilation et tests YARA dans un processus séparé et borné."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from cyber_harness.evidence import canonical, digest, read_bytes


def evaluate_yara(
    rule_text: str, incident: Path, benign: Path, corpus: dict, timeout: float = 8
) -> dict:
    result = {
        "compile": False,
        "test_concluant": False,
        "verdict": "À REVOIR",
        "regle_sha256": digest(rule_text.encode()),
    }
    try:
        if len(rule_text) > 20_000:
            raise ValueError("Règle trop volumineuse")
        if not corpus["malveillants"] or not corpus["benins"]:
            raise ValueError("Corpus malveillant et bénin requis")
        samples, hashes = [], {}
        for kind, root in (("malveillants", incident), ("benins", benign)):
            for name in corpus[kind]:
                raw = read_bytes(root, name, 1_000_000)
                key = kind + "/" + name
                hashes[key] = digest(raw)
                samples.append({"name": key, "data": base64.b64encode(raw).decode()})
        result["corpus_sha256"] = digest(canonical(hashes).encode())
        # Aucun secret ni configuration réseau transmis au processus de compilation.
        worker = Path(__file__).with_name("yara_worker.py")
        run = subprocess.run(
            [sys.executable, "-I", str(worker)],
            input=json.dumps({"rule": rule_text, "samples": samples}),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": os.defpath},
        )
        if run.returncode:
            raise ValueError(f"Processus YARA interrompu ({run.returncode})")
        parsed = json.loads(run.stdout)
        if not parsed.get("test_concluant"):
            result.update(parsed)
            return result
        hits = set(parsed["hits"])
        vp = [n for n in corpus["malveillants"] if "malveillants/" + n in hits]
        fn = [n for n in corpus["malveillants"] if n not in vp]
        fp = [n for n in corpus["benins"] if "benins/" + n in hits]
        result.update(
            compile=True,
            test_concluant=True,
            vrais_positifs=vp,
            faux_negatifs=fn,
            faux_positifs=fp,
            nb_scripts_legitimes_testes=len(corpus["benins"]),
            verdict="OK" if vp and not fp and not fn else "À REVOIR",
        )
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        result["erreur"] = f"{type(exc).__name__}: {exc}"
    return result
