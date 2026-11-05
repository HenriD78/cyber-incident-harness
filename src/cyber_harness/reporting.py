"""Assemblage du rapport depuis les seuls états et résultats enregistrés."""

import json

from cyber_harness.evidence import canonical
from cyber_harness.models import Reference


def citations(refs):
    return ", ".join(
        dict.fromkeys(
            f"{r.fichier}:{r.ligne}" if isinstance(r, Reference) else f"{r['fichier']}:{r['ligne']}"
            for r in refs
        )
    )


def render_report(session, errors):
    lines = [
        "# Rapport d'incident INC-2026-0417",
        "",
        "**Statut : "
        + ("INCOMPLET / NON VALIDÉ" if errors else "COMPLET — contrôles structurels réussis")
        + "**",
        "",
        "## Résumé exécutif",
        "",
        session.summary.resume
        if session.summary
        else "Synthèse non vérifiée : clôture de secours.",
    ]
    if session.summary and session.analysis:
        lines += [
            "Sources : "
            + citations(
                [r for f in session.finding_ids(session.summary.constat_ids) for r in f.preuves]
            )
        ]
    if session.analysis:
        lines += ["", "## Qualification et lien entre alertes", ""]
        for name, qualification in session.analysis.qualifications.items():
            refs = [r for f in session.finding_ids(qualification.constat_ids) for r in f.preuves]
            lines.append(f"- {name} : {qualification.conclusion} ({citations(refs)}).")
        lines += [
            "",
            ("Lien affirmé : " if session.analysis.lien_prouve else "Aucun lien prouvé : ")
            + session.analysis.lien_alertes,
            "Sources du lien : " + (citations(session.analysis.preuves_lien) or "non vérifié"),
            "",
            "## Chronologie et constats",
            "",
        ]
        for f in sorted(session.analysis.constats, key=lambda f: f.utc or "~"):
            lines.append(
                f"- {f.id} — {f.utc or 'date non vérifiée'} — {f.statut} : {f.description} ({citations(f.preuves)})."
            )
    lines += ["", "## IOC vérifiés", ""]
    for i in session.iocs or []:
        lines.append(
            f"- {i.type} `{i.valeur}` : {i.contexte} ; confiance {i.confiance} ; {citations(i.references)} ; constats {', '.join(i.constat_ids)}"
            + (f" ; dérivation {i.derivation_id}" if i.derivation_id else "")
        )
    lines += [
        "",
        "## MITRE ATT&CK",
        "",
        canonical(session.reference.metadata) if session.reference else "Référentiel indisponible",
    ]
    for m in session.mappings or []:
        lines.append(
            f"- {m['id']} — {m['nom']} ({', '.join(m['tactiques'])}) : {m['justification']}"
        )
        for f in m["constats"]:
            lines.append(f"  - {f['id']} : {f['statut']} ; {citations(f['preuves'])}")
    lines += [
        "",
        "## Règles et résultats exacts",
        "",
        "Fichiers : regle_sigma.yml, regle_yara.yar. Résultats locaux, sans certification de déploiement SIEM.",
        "```json",
        json.dumps(session.tests, ensure_ascii=False, indent=2),
        "```",
        "",
        "## Confinement et décision humaine",
        "",
        "```json",
        json.dumps(
            {
                "proposition": session.proposal.model_dump() if session.proposal else None,
                "decision": session.decision,
            },
            ensure_ascii=False,
            indent=2,
        ),
        "```",
        "Aucune action exécutée par l'agent.",
    ]
    if session.protocol:
        lines += [
            "Protocole manuel détaillé : [protocole_confinement.md](protocole_confinement.md)."
        ]
    if session.decision and session.decision["decision"] == "refusee":
        lines += ["Proposition refusée : aucune nouvelle proposition ni protocole."]
    lines += [
        "",
        "## Tentatives d'injection dans les preuves",
        "",
        citations(session.analysis.injections)
        if session.analysis and session.analysis.injections
        else "Aucune référence signalée ; absence non garantie.",
        "",
        "## Limites et points à confirmer",
        "",
        "Les contrôles vérifient les sources et la cohérence des artefacts ; la pertinence des interprétations reste à relire par l'analyste.",
    ]
    limits = (
        errors
        + (session.analysis.limites if session.analysis else [])
        + (session.summary.limites if session.summary else [])
    )
    lines += [f"- {item}" for item in dict.fromkeys(limits)]
    lines += [
        "",
        "## État des phases",
        "",
        "```json",
        json.dumps(session.phase_status, ensure_ascii=False, indent=2),
        "```",
        "",
        "Traçabilité : audit.jsonl, etat_phases.json, manifest_preuves.json, resultats_tests.json et validation_finale.json.",
    ]
    session.save("rapport_incident.md", "\n".join(lines) + "\n", text=True)
