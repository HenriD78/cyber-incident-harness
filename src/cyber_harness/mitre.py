"""Référentiel officiel : mise à jour bornée, remplacement atomique et snapshot par run."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

from cyber_harness.evidence import atomic_write, digest, read_bytes

INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
PREFIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"


def fetch_json(url: str) -> bytes:
    if url != INDEX and not re.fullmatch(
        re.escape(PREFIX) + r"enterprise-attack-\d+\.\d+\.json", url
    ):
        raise ValueError("URL MITRE non autorisée")
    with urlopen(url, timeout=15) as response:
        if response.url != url:
            raise ValueError("Redirection MITRE inattendue")
        data = response.read(100_000_001)
    if len(data) > 100_000_000:
        raise ValueError("Référentiel trop volumineux")
    return data


class MitreReference:
    def __init__(self, raw: bytes, freshness: dict | None = None):
        bundle = json.loads(raw)
        collections = [o for o in bundle["objects"] if o["type"] == "x-mitre-collection"]
        if len(collections) != 1 or collections[0].get("name") != "Enterprise ATT&CK":
            raise ValueError("Collection ATT&CK Enterprise absente ou ambiguë")
        self.version = collections[0]["x_mitre_version"]
        self.metadata = {"version": self.version, "sha256": digest(raw), **(freshness or {})}
        self.index = {}
        by_stix = {}
        revoked = {}
        for obj in bundle["objects"]:
            if obj["type"] == "relationship" and obj.get("relationship_type") == "revoked-by":
                revoked[obj["source_ref"]] = obj["target_ref"]
            if obj["type"] != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    entry = {
                        "id": ref["external_id"],
                        "nom": obj["name"],
                        "description": obj.get("description", ""),
                        "plateformes": obj.get("x_mitre_platforms", []),
                        "tactiques": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                        "url": ref.get("url"),
                        "revoquee": obj.get("revoked", False),
                        "obsolete": obj.get("x_mitre_deprecated", False),
                        "version_attack": self.version,
                    }
                    self.index[entry["id"]] = entry
                    by_stix[obj["id"]] = entry
        if not self.index:
            raise ValueError("Référentiel sans technique")
        for source, target in revoked.items():
            if source in by_stix and target in by_stix:
                by_stix[source]["remplacee_par"] = by_stix[target]["id"]

    def check(self, technique: str) -> dict:
        entry = self.index.get(technique.strip().upper())
        if entry is None:
            raise ValueError(f"{technique} : identifiant inexistant dans ATT&CK {self.version}")
        result = dict(entry)
        if entry["revoquee"] or entry["obsolete"]:
            result["avertissement"] = "Technique révoquée/obsolète : vérifier son remplaçant"
        return result

    def search(self, query: str) -> list[dict]:
        terms = query.lower().split()
        ranked = []
        for entry in self.index.values():
            if entry["revoquee"] or entry["obsolete"]:
                continue
            text = (entry["nom"] + " " + entry["description"]).lower()
            score = sum(text.count(t) for t in terms)
            if score:
                ranked.append((score, entry))
        return [
            dict(e, description=e["description"][:2500])
            for _, e in sorted(ranked, key=lambda pair: (-pair[0], pair[1]["id"]))[:5]
        ]


def refresh_reference(path: Path, fetch=fetch_json) -> MitreReference:
    local = read_bytes(path.parent, path.name, 100_000_000) if path.exists() else None
    freshness = {
        "verifie_le": datetime.now(timezone.utc).isoformat(),
        "source": INDEX,
        "fraicheur": "non_verifiee",
    }
    try:
        index = json.loads(fetch(INDEX))
        versions = [
            v for c in index["collections"] for v in c["versions"] if v["url"].startswith(PREFIX)
        ]
        latest = max(versions, key=lambda v: tuple(int(p) for p in v["version"].split(".")))
        try:
            current = MitreReference(local) if local else None
        except (ValueError, KeyError, TypeError):
            current = None
        freshness["derniere_version"] = latest["version"]
        if current is None or current.version != latest["version"]:
            raw = fetch(latest["url"])
            candidate = MitreReference(raw)
            if candidate.version != latest["version"]:
                raise ValueError("Version téléchargée incohérente avec l'index")
            atomic_write(path.parent, path.name, raw.decode("utf-8"))
            local = raw
        freshness["fraicheur"] = "a_jour"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        freshness["erreur"] = f"{type(exc).__name__}: {exc}"
    if local is None:
        raise ValueError("Référentiel absent et téléchargement impossible")
    return MitreReference(local, freshness)
