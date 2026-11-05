"""Évaluation locale du sous-ensemble Sigma pris en charge."""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
    ConditionValueExpression,
)
from sigma.types import SigmaBool, SigmaNull, SigmaNumber, SigmaString, SpecialChars

from cyber_harness.evidence import canonical, digest, read_bytes

SIGMA_TO_EDR = {
    "Image": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image",
    "User": "user",
    "Computer": "host",
    "TargetFilename": "path",
    "QueryName": "query",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "Hashes": "sha256",
}


def _sigma_to_regex(s: SigmaString, keyword: bool = False) -> re.Pattern:
    parts = []
    for p in s.s:
        if p == SpecialChars.WILDCARD_MULTI:
            parts.append("*")
        elif p == SpecialChars.WILDCARD_SINGLE:
            parts.append("?")
        else:
            parts.append("".join({"[": "[[]", "*": "[*]", "?": "[?]"}.get(c, c) for c in str(p)))
    pattern = "".join(parts)
    if keyword:
        pattern = "*" + pattern + "*"
    # Python 3.11+ traduit les étoiles intérieures en groupes atomiques : pas de
    # backtracking exponentiel provoqué par une suite de jokers générée par le LLM.
    return re.compile(fnmatch.translate(pattern), re.I | re.S)


def _match_value(item, event: dict) -> bool:
    # Une recherche par mots-clés (ConditionValueExpression) n'a pas de champ.
    field = (
        SIGMA_TO_EDR.get(item.field, item.field)
        if isinstance(item, ConditionFieldEqualsValueExpression)
        else None
    )
    candidates = [event.get(field)] if field is not None else list(event.values())
    # Sigma est insensible à la casse par défaut ; les modificateurs (contains,
    # endswith...) ont déjà été traduits en jokers par pySigma.
    regex = (
        _sigma_to_regex(item.value, keyword=field is None)
        if type(item.value) is SigmaString
        else None
    )
    if type(item.value) not in (SigmaString, SigmaNumber, SigmaBool, SigmaNull):
        raise ValueError(f"Expression Sigma non supportée : {type(item.value).__name__}")
    for c in candidates:
        if isinstance(item.value, SigmaNull):
            if c is None:
                return True
            continue
        if c is None:
            continue
        if regex is not None:
            if regex.fullmatch(str(c)):
                return True
        elif isinstance(item.value, SigmaBool):
            if isinstance(c, bool) and c == item.value.boolean:
                return True
        elif isinstance(item.value, SigmaNumber):
            if isinstance(c, (int, float)) and not isinstance(c, bool) and c == item.value.number:
                return True
    return False


def _eval(node, event: dict, detection) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event, detection) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event, detection) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event, detection)
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        return _match_value(node, event)
    if isinstance(node, (ConditionIdentifier, ConditionSelector)):
        raise ValueError("condition non résolue")
    raise ValueError(f"élément de condition non supporté : {type(node).__name__}")


def _check_sigma_node(node):
    # Examiner toutes les branches, même si une évaluation booléenne court-circuite.
    if isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
        for child in node.args:
            _check_sigma_node(child)
    elif isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        if type(node.value) not in (SigmaString, SigmaNumber, SigmaBool, SigmaNull):
            raise ValueError(f"Expression Sigma non supportée : {type(node.value).__name__}")
        if isinstance(node, ConditionFieldEqualsValueExpression) and node.field not in SIGMA_TO_EDR:
            raise ValueError(f"Champ Sigma non supporté : {node.field}")
    else:
        raise ValueError(f"Condition Sigma non supportée : {type(node).__name__}")


def evaluate_sigma(rule_yaml: str, incident: Path, corpus: dict | None = None) -> dict:
    result = {
        "valide": False,
        "test_concluant": False,
        "test_reussi": False,
        "detections_sur_edr": [],
        "regle_sha256": digest(rule_yaml.encode()),
    }
    try:
        if len(rule_yaml) > 20_000:
            raise ValueError("Règle trop volumineuse")
        coll = SigmaCollection.from_yaml(rule_yaml)
        if len(coll.rules) != 1 or coll.errors or coll.rules[0].errors:
            raise ValueError("Une seule règle Sigma valide est requise")
        rule = coll.rules[0]
        conds = [c.parsed for c in rule.detection.parsed_condition]
        result.update(valide=True, titre=rule.title, logsource=str(rule.logsource))
        if (
            rule.logsource.product != "windows"
            or rule.logsource.category != "process_creation"
            or rule.logsource.service
        ):
            raise ValueError(
                "Logsource non pris en charge : windows/process_creation sans service requis"
            )
        for cond in conds:
            _check_sigma_node(cond)
        raw = read_bytes(incident, "edr_events.jsonl")
        events = [
            (n, json.loads(line))
            for n, line in enumerate(raw.decode().splitlines(), 1)
            if line.strip()
        ]
        hits = [
            n
            for n, ev in events
            if ev.get("event") == "process_create"
            and any(_eval(c, ev, rule.detection) for c in conds)
        ]
        result.update(
            test_concluant=True,
            test_reussi=bool(hits),
            detections_sur_edr=[f"edr_events.jsonl:{n} (process_create)" for n in hits],
            corpus_sha256=digest(raw),
        )
        if corpus is not None:
            positives = {
                r["ligne"] for r in corpus["positifs"] if r["fichier"] == "edr_events.jsonl"
            }
            if (
                not positives
                or not corpus["negatifs"]
                or not positives.issubset({n for n, _ in events})
            ):
                raise ValueError("Corpus annoté positif/négatif absent ou incohérent")
            fp = [f"edr_events.jsonl:{n}" for n in hits if n not in positives]
            fp += [
                f"benin:{n}"
                for n, ev in enumerate(corpus["negatifs"], 1)
                if ev.get("event") == "process_create"
                and any(_eval(c, ev, rule.detection) for c in conds)
            ]
            fn = [f"edr_events.jsonl:{n}" for n in sorted(positives - set(hits))]
            result.update(
                faux_positifs=fp,
                faux_negatifs=fn,
                test_reussi=bool(hits) and not fp and not fn,
                corpus_sha256=digest(raw + canonical(corpus).encode()),
                nb_negatifs=len(corpus["negatifs"]),
            )
        if not hits:
            result["test"] = "la règle ne détecte AUCUN événement de l'incident : à revoir"
    except Exception as exc:
        result.update(
            test_concluant=False,
            test_reussi=False,
            detections_sur_edr=[],
            erreur=f"{type(exc).__name__}: {exc}",
            test=f"test non concluant : {type(exc).__name__}: {exc}",
        )
    return result
