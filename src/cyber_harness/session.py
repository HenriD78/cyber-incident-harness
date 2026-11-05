"""État métier détenu par l'hôte, outils typés et validation des livrables.

Les décisions humaines ne sont pas des arguments d'outil. Les outils du modèle
ne peuvent ni choisir une phase, ni écrire dans le registre d'approbation.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from langchain_core.tools import StructuredTool, ToolException
from pydantic import ConfigDict, create_model

from cyber_harness.config import RunSettings
from cyber_harness.detection import evaluate_sigma, evaluate_yara
from cyber_harness.evidence import (
    EvidenceStore,
    atomic_write,
    canonical,
    contains_indicator,
    decode_static,
    digest,
    read_bytes,
)
from cyber_harness.mitre import MitreReference
from cyber_harness.models import (
    IOC,
    Analysis,
    Mapping,
    Proposal,
    Protocol,
    ReportSummary,
)
from cyber_harness.reporting import citations, render_report
from cyber_harness.runtime.audit import AuditLog
from cyber_harness.runtime.feedback import BusinessValidationError, ToolFeedback
from cyber_harness.tools import to_utc

PHASES = ("preuves", "ioc", "mitre", "regles", "confinement", "protocole", "rapport")
SKILLS = {
    "preuves": "analyse-preuves",
    "ioc": "extraction-ioc",
    "mitre": "mapping-mitre",
    "regles": "regles-detection",
    "confinement": "confinement",
    "protocole": "confinement",
    "rapport": "rapport-incident",
}

# Un mapping décrit les comportements et peut être produit même si l'extraction
# des IOC échoue. De même, un test de détection négatif n'interdit pas de proposer
# un confinement justifié par des constats et IOC vérifiés.
DEPENDENCIES = {
    "preuves": (),
    "ioc": ("preuves",),
    "mitre": ("preuves",),
    "regles": ("preuves", "mitre"),
    "confinement": ("preuves", "ioc"),
    "protocole": ("confinement",),
    "rapport": ("preuves",),
}
PHASE_OUTPUTS = {
    "preuves": ("analyse.json", "chronologie.md"),
    "ioc": ("iocs.json",),
    "mitre": ("mitre.json",),
    "regles": ("regle_sigma.yml", "regle_yara.yar", "resultats_tests.json"),
    "confinement": ("proposition_confinement.json",),
    "protocole": ("protocole_confinement.json", "protocole_confinement.md"),
    "rapport": ("synthese_rapport.json",),
}
PHASE_WRITERS = {
    "preuves": ("save_analysis",),
    "ioc": ("save_iocs",),
    "mitre": ("save_mitre",),
    "regles": ("validate_sigma", "test_yara"),
    "confinement": ("propose_containment",),
    "protocole": ("save_protocol",),
    "rapport": ("save_report_summary",),
}


class Session:
    def __init__(
        self,
        base: Path,
        output: Path,
        reference: MitreReference | None,
        thread_id: str,
        *,
        skills_dir: Path | None = None,
        settings: RunSettings | None = None,
    ):
        self.base, self.output, self.reference = base, output, reference
        self.skills_dir = skills_dir if skills_dir is not None else base / "skills"
        self.settings = settings if settings is not None else RunSettings.from_environment()
        self.evidence = EvidenceStore(base / "incident")
        self.corpus = json.loads(read_bytes(base, "detection_corpus.json"))
        self.corpus_raw = canonical(self.corpus)
        self.audit = AuditLog(output, thread_id)
        self.lock = RLock()
        self.stage = None
        self.analysis = None
        self.iocs = None
        self.mappings = None
        self.proposal = None
        self.decision = None
        self.protocol = None
        self.summary = None
        self.verified_iocs = {}
        self.derivations = {}
        self.checked_mitre = set()
        self.tests = {}
        self.attempts = {"sigma": 0, "yara": 0}
        self.artifacts = {}
        self.errors = []
        self.phase_status = {}
        self.feedback = ToolFeedback(self)
        self.audit.event(
            "initialisation",
            {
                "preuves": self.evidence.hashes,
                "mitre": reference.metadata if reference else None,
                "corpus_sha256": digest(self.corpus_raw.encode()),
            },
        )
        self.save("manifest_preuves.json", self.evidence.hashes)
        self.save(
            "referentiel.json",
            reference.metadata if reference else {"erreur": "Référentiel indisponible"},
        )

    def save(self, name, value, *, text=False):
        content = value if text else json.dumps(value, ensure_ascii=False, indent=2)
        atomic_write(self.output, name, content)
        self.artifacts[name] = digest(content.encode())
        self.audit.event(
            "livrable", {"fichier": name, "sha256": self.artifacts[name], "phase": self.stage}
        )

    def refs(self, refs):
        for ref in refs:
            self.evidence.validate(ref)

    def finding_ids(self, ids, *, actionable=False):
        found = {f.id: f for f in self.analysis.constats} if self.analysis else {}
        if not ids or len(set(ids)) != len(ids) or any(i not in found for i in ids):
            raise ValueError("Identifiants de constats inconnus/dupliqués")
        if actionable and any(found[i].statut == "hypothese" for i in ids):
            raise ValueError("Une hypothèse seule ne justifie pas un confinement")
        return [found[i] for i in ids]

    def enter(self, stage):
        if stage not in PHASES:
            raise ValueError("Phase inconnue")
        if self.stage is not None and PHASES.index(stage) <= PHASES.index(self.stage):
            raise ValueError("Retour de phase interdit")
        if stage == "protocole" and (not self.decision or self.decision["decision"] != "acceptee"):
            raise ValueError("Protocole interdit sans accord")
        self.stage = stage
        self.audit.event("phase", {"phase": stage})

    def require(self, stage):
        if self.stage != stage:
            raise ValueError(f"Outil réservé à la phase {stage}")

    def artifact_issues(self, names):
        errors = []
        for name in names:
            if name not in self.artifacts:
                errors.append(f"Livrable non enregistré : {name}")
                continue
            try:
                if digest(read_bytes(self.output, name, 100_000_000)) != self.artifacts[name]:
                    errors.append(f"Livrable modifié : {name}")
            except (OSError, ValueError):
                errors.append(f"Livrable absent/inaccessible : {name}")
        return errors

    def phase_issues(self, stage):
        """Vérifier les postconditions réelles, pas le texte final de l'assistant."""
        errors = self.artifact_issues(PHASE_OUTPUTS[stage])
        attr = {
            "preuves": "analysis",
            "ioc": "iocs",
            "mitre": "mappings",
            "confinement": "proposal",
            "protocole": "protocol",
            "rapport": "summary",
        }.get(stage)
        if attr and getattr(self, attr) is None:
            errors.append(f"État métier non enregistré : {attr}")
        if not self.evidence.intact():
            errors.append("Intégrité des preuves compromise")
        if stage == "preuves" and not self.evidence.complete():
            errors.append("Lecture des preuves incomplète")
        if stage == "mitre" and self.reference is None:
            errors.append("Référentiel MITRE indisponible")
        if stage == "regles":
            for kind in ("sigma", "yara"):
                result = self.tests.get(kind, {})
                passed = (
                    result.get("test_reussi") if kind == "sigma" else result.get("verdict") == "OK"
                )
                if not result.get("test_concluant") or not passed:
                    errors.append(f"Test {kind} non réussi ({self.attempts[kind]}/4 essais)")
        if stage == "protocole" and (not self.decision or self.decision["decision"] != "acceptee"):
            errors.append("Accord humain absent")
        return errors

    def dependency_issues(self, stage):
        errors = []
        for dependency in DEPENDENCIES[stage]:
            state = self.phase_status.get(dependency, {}).get("statut")
            issues = self.phase_issues(dependency)
            if state in {"echec", "bloquee"}:
                errors.append(f"Prérequis {dependency} : phase {state}")
            elif issues:
                errors.append(f"Prérequis {dependency} : " + "; ".join(issues))
        if stage == "protocole" and (not self.decision or self.decision["decision"] != "acceptee"):
            errors.append("Accord humain absent")
        return errors

    def record_phase(self, stage, status, issues=(), invocations=0):
        self.phase_status[stage] = {
            "statut": status,
            "raisons": list(issues),
            "invocations": invocations,
        }
        self.audit.event("etat_phase", {"phase": stage, **self.phase_status[stage]})
        self.save("etat_phases.json", self.phase_status)

    def phase_retryable(self, stage):
        if not self.evidence.intact():
            return False
        if stage == "regles":
            return any(
                self.attempts[k] < 4
                and (
                    not self.tests.get(k, {}).get("test_concluant")
                    or not (
                        self.tests[k].get("test_reussi")
                        if k == "sigma"
                        else self.tests[k].get("verdict") == "OK"
                    )
                )
                for k in ("sigma", "yara")
            )
        return True

    def save_analysis(self, analysis: Analysis):
        self.require("preuves")
        if not self.evidence.complete():
            raise ValueError("Lire toutes les pages de toutes les preuves avant de conclure")
        if len({f.id for f in analysis.constats}) != len(analysis.constats):
            raise ValueError("Identifiants de constats dupliqués")
        for f in analysis.constats:
            self.refs(f.preuves)
            if bool(f.utc) != bool(f.horodatage_source):
                raise ValueError("Horodatage source et UTC doivent être fournis ensemble")
            if f.utc:
                if to_utc.invoke(f.horodatage_source) != f.utc:
                    raise ValueError("Conversion UTC incohérente")
                if not any(
                    f.horodatage_source in self.evidence.content[r.fichier][r.ligne - 1]
                    for r in f.preuves
                ):
                    raise ValueError("Horodatage absent des références")
        self.refs(analysis.preuves_lien)
        self.refs(analysis.injections)
        if set(analysis.qualifications) != {"alerte_web", "alerte_poste"}:
            raise ValueError("Qualifier alerte_web et alerte_poste")
        ids = {f.id for f in analysis.constats}
        for qualification in analysis.qualifications.values():
            if any(i not in ids for i in qualification.constat_ids):
                raise ValueError("Qualification sans constats vérifiés")
        if analysis.lien_prouve and not analysis.preuves_lien:
            raise ValueError("Un lien affirmé exige des preuves")
        self.analysis = analysis
        self.save("analyse.json", analysis.model_dump())
        rows = [
            "# Chronologie UTC",
            "",
            "| UTC | Constat | Statut | Preuves |",
            "|---|---|---|---|",
        ]
        for finding in sorted(analysis.constats, key=lambda f: f.utc or "~"):
            rows.append(
                f"| {finding.utc or 'non vérifié'} | {finding.id} : {finding.description} | {finding.statut} | {citations(finding.preuves)} |"
            )
        self.save("chronologie.md", "\n".join(rows), text=True)
        return "Analyse et chronologie enregistrées"

    def verify(self, value):
        refs = self.evidence.occurrences(value)
        self.verified_iocs[value] = refs
        return {
            "valeur": value,
            "references": refs,
            "contexte": "Présence textuelle seulement ; justifier le rôle dans l'incident",
        }

    def decode(self, file, line, encoded):
        ref = self.evidence.reference(file, line)
        if encoded not in self.evidence.content[file][line - 1]:
            raise ValueError("La chaîne encodée n'est pas présente à cette ligne")
        decoded = decode_static(encoded)
        derivation_id = digest(canonical({"source": ref, "encoded": encoded}).encode())
        record = dict(
            decoded, id=derivation_id, source=ref, transformation="base64/" + decoded["encodage"]
        )
        self.derivations[derivation_id] = record
        self.save("derivations.json", list(self.derivations.values()))
        return record

    def save_iocs(self, iocs):
        self.require("ioc")
        if len({i.valeur for i in iocs}) != len(iocs):
            raise ValueError("Dédupliquer les IOC par valeur")
        errors = []
        for index, ioc in enumerate(iocs):
            location = {"champ": f"iocs.{index}.references", "valeur": ioc.valeur}
            try:
                self.refs(ioc.references)
                self.finding_ids(ioc.constat_ids)
                if ioc.derivation_id:
                    derived = self.derivations.get(ioc.derivation_id)
                    if not derived or not contains_indicator(ioc.valeur, derived["texte_decode"]):
                        raise ValueError("IOC absent du décodage vérifié")
                    if [r.model_dump() for r in ioc.references] != [derived["source"]]:
                        errors.append(
                            {
                                **location,
                                "message": "Référencer uniquement la ligne encodée de l'IOC dérivé",
                                "references_attendues": [derived["source"]],
                            }
                        )
                else:
                    refs = self.verified_iocs.get(ioc.valeur)
                    if refs is None:
                        errors.append(
                            {
                                **location,
                                "message": "Appeler verify_ioc pour cette valeur avant de l'enregistrer",
                                "appel_requis": {
                                    "outil": "verify_ioc",
                                    "arguments": {"value": ioc.valeur},
                                },
                            }
                        )
                    elif not refs:
                        errors.append(
                            {
                                **location,
                                "message": "IOC absent des preuves en clair ; une dérivation exige sa provenance",
                            }
                        )
                    else:
                        expected = Counter(canonical(r) for r in refs)
                        provided = Counter(canonical(r.model_dump()) for r in ioc.references)
                        if expected != provided:
                            errors.append(
                                {
                                    **location,
                                    "message": f"Références incomplètes ou en trop : {sum((expected - provided).values())} manquante(s), "
                                    f"{sum((provided - expected).values())} inattendue(s). "
                                    "Conserver toutes les occurrences exactes renvoyées par verify_ioc, sans doublon",
                                    "references_manquantes": [
                                        json.loads(r)
                                        for r in sorted((expected - provided).elements())
                                    ],
                                    "references_inattendues": [
                                        json.loads(r)
                                        for r in sorted((provided - expected).elements())
                                    ],
                                    "nombre_attendu": sum(expected.values()),
                                    "nombre_recu": sum(provided.values()),
                                }
                            )
            except ValueError as exc:
                errors.append({"champ": f"iocs.{index}", "valeur": ioc.valeur, "message": str(exc)})
        if errors:
            # Vérifier tout le lot avant toute écriture : corriger un IOC ne doit
            # pas masquer une seconde erreur jusqu'à l'essai suivant.
            raise BusinessValidationError(errors)
        self.iocs = iocs
        self.save("iocs.json", [i.model_dump() for i in iocs])
        return "IOC vérifiés enregistrés"

    def check_mitre(self, technique_id):
        if self.reference is None:
            raise ValueError("Référentiel indisponible")
        result = self.reference.check(technique_id)
        self.checked_mitre.add(result["id"])
        return result

    def save_mappings(self, associations):
        self.require("mitre")
        result = []
        for association in associations:
            if not self.reference or association.id not in self.checked_mitre:
                raise ValueError("Vérifier chaque technique avec check_mitre")
            official = self.reference.check(association.id)
            if official["revoquee"] or official["obsolete"]:
                raise ValueError("Technique révoquée/obsolète interdite")
            findings = self.finding_ids(association.constat_ids)
            result.append(
                {
                    **official,
                    **association.model_dump(),
                    "constats": [f.model_dump() for f in findings],
                }
            )
        self.mappings = result
        self.save("mitre.json", result)
        return "Associations MITRE enregistrées"

    def test_rule(self, kind, rule):
        self.require("regles")
        if self.attempts[kind] >= 4:
            raise ValueError("Quatre tentatives déjà utilisées pour cette règle")
        self.attempts[kind] += 1
        name = "regle_sigma.yml" if kind == "sigma" else "regle_yara.yar"
        self.save(name, rule, text=True)
        if kind == "sigma":
            result = evaluate_sigma(rule, self.base / "incident", self.corpus["sigma"])
        else:
            result = evaluate_yara(
                rule, self.base / "incident", self.base / "benign_samples", self.corpus["yara"]
            )
        result["tentative"] = self.attempts[kind]
        self.tests[kind] = result
        self.save(f"tests/{kind}-{self.attempts[kind]}.json", result)
        self.save("resultats_tests.json", self.tests)
        return result

    def containment_context(self):
        """Identifiants et sources vérifiés, sans choisir d'action ni d'approbation."""
        return {
            "cibles_ioc_verifiees": [
                {"cible": i.valeur, "type": i.type, "constat_ids": i.constat_ids}
                for i in (self.iocs or [])
            ],
            "constats_actionnables": [
                {
                    "id": f.id,
                    "description": f.description,
                    "preuves": [r.model_dump() for r in f.preuves],
                }
                for f in (self.analysis.constats if self.analysis else [])
                if f.statut != "hypothese"
            ],
            "consigne_cible": "cible contient uniquement l'identifiant exact, par exemple admin et non compte admin. "
            "Décrire le type, le périmètre et le système concerné dans action et justification. "
            "Une cible hors de cette liste doit être prouvée dans les preuves ; ne pas l'inventer.",
        }

    def propose(self, proposal):
        self.require("confinement")
        if not self.evidence.intact():
            raise ValueError("Preuves modifiées : proposition de confinement interdite")
        if self.proposal or self.decision:
            raise ValueError("Une seule proposition consolidée par incident")
        if len({a.id for a in proposal.actions}) != len(proposal.actions):
            raise ValueError("Identifiants d'actions dupliqués")
        errors = []
        for index, action in enumerate(proposal.actions):
            location = {"action_id": action.id, "valeur": action.cible}
            try:
                self.refs(action.preuves)
            except ValueError as exc:
                errors.append(
                    {**location, "champ": f"proposal.actions.{index}.preuves", "message": str(exc)}
                )
            try:
                findings = self.finding_ids(action.constat_ids, actionable=True)
            except ValueError as exc:
                errors.append(
                    {
                        **location,
                        "champ": f"proposal.actions.{index}.constat_ids",
                        "message": str(exc),
                    }
                )
            else:
                allowed = {canonical(r.model_dump()) for f in findings for r in f.preuves}
                unexpected = [
                    r.model_dump()
                    for r in action.preuves
                    if canonical(r.model_dump()) not in allowed
                ]
                if unexpected:
                    errors.append(
                        {
                            **location,
                            "champ": f"proposal.actions.{index}.preuves",
                            "message": "Les preuves doivent appartenir aux constats invoqués",
                            "references_inattendues": unexpected,
                            "references_attendues": [json.loads(r) for r in sorted(allowed)],
                        }
                    )
            # La cible doit être observable dans une preuve ou un IOC vérifié.
            if not self.evidence.occurrences(action.cible) and not any(
                i.valeur == action.cible for i in (self.iocs or [])
            ):
                errors.append(
                    {
                        **location,
                        "champ": f"proposal.actions.{index}.cible",
                        "message": f"Cible non vérifiée dans les preuves/IOC : {action.cible}. "
                        "Utiliser uniquement un identifiant exact ; placer sa description dans action ou justification.",
                        "cibles_ioc_verifiees": [i.valeur for i in (self.iocs or [])],
                    }
                )
        if errors:
            raise BusinessValidationError(errors)
        self.proposal = proposal
        self.save("proposition_confinement.json", proposal.model_dump())
        return "Proposition enregistrée, décision exclusivement par la console humaine après cette phase"

    def decide(self, accepted: bool, reason: str = ""):
        """API hôte uniquement ; jamais exposée comme outil du modèle."""
        if self.stage != "confinement" or not self.proposal or self.decision:
            raise ValueError("Décision hors contexte ou déjà prise")
        if not isinstance(accepted, bool) or not self.evidence.intact():
            raise ValueError("Décision booléenne explicite et preuves intactes requises")
        self.decision = {
            "decision": "acceptee" if accepted else "refusee",
            "proposition_sha256": digest(canonical(self.proposal.model_dump()).encode()),
            "acteur": "analyste_console",
            "motif": reason,
            "utc": datetime.now(timezone.utc).isoformat(),
            "execution": "jamais_executee_par_agent",
        }
        self.save("containment.json", self.decision)
        self.audit.event("decision_humaine", self.decision)

    def save_protocol(self, protocol):
        self.require("protocole")
        if not self.decision or self.decision["decision"] != "acceptee":
            raise ValueError("Accord humain absent")
        if not self.evidence.intact():
            raise ValueError("Preuves modifiées après approbation")
        if protocol.proposition_sha256 != self.decision["proposition_sha256"]:
            raise ValueError("Accord portant sur une autre proposition")
        approved = {a.id: a for a in self.proposal.actions}
        if {a.action_id for a in protocol.actions} != set(approved) or len(protocol.actions) != len(
            approved
        ):
            raise ValueError("Le protocole doit couvrir exactement les actions approuvées")
        for action in protocol.actions:
            if action.cible != approved[action.action_id].cible:
                raise ValueError("Cible différente de la cible approuvée")
        self.protocol = protocol
        self.save("protocole_confinement.json", protocol.model_dump())
        lines = [
            "# Protocole manuel de confinement",
            "",
            "Aucune action exécutée par l'agent. Vérifier les prérequis avant application.",
            f"Proposition approuvée : `{protocol.proposition_sha256}`",
            "",
        ]
        for action in protocol.actions:
            lines += [
                f"## {action.action_id} — {approved[action.action_id].action}",
                f"Cible : {action.cible}. Responsable : {action.responsable}.",
            ]
            for key in ("prerequis", "etapes", "verifications", "criteres_arret", "retour_arriere"):
                lines += ["", f"### {key}", ""] + [
                    f"{n}. {item}" for n, item in enumerate(getattr(action, key), 1)
                ]
        self.save("protocole_confinement.md", "\n".join(lines), text=True)
        return "Protocole manuel enregistré"

    def save_summary(self, summary):
        self.require("rapport")
        self.finding_ids(summary.constat_ids)
        self.summary = summary
        self.save("synthese_rapport.json", summary.model_dump())
        return (
            "Synthèse enregistrée ; le harness assemblera le rapport sourcé et les résultats exacts"
        )

    def validate(self, *, require_report=False):
        errors = list(self.errors)
        errors.extend(
            f"{stage} : {state['statut']} — " + "; ".join(state["raisons"])
            for stage, state in self.phase_status.items()
            if state["statut"] in {"echec", "bloquee"}
        )
        if not self.evidence.complete():
            errors.append("Lecture des preuves incomplète")
        if not self.evidence.intact():
            errors.append("Intégrité des preuves compromise")
        errors.extend(self.artifact_issues(self.artifacts))
        for attr in ("analysis", "iocs", "mappings", "proposal", "decision", "summary"):
            if getattr(self, attr) is None:
                errors.append(f"Étape incomplète : {attr}")
        if not self.reference or self.reference.metadata.get("fraicheur") != "a_jour":
            errors.append("Fraîcheur MITRE non vérifiée")
        try:
            if (
                canonical(json.loads(read_bytes(self.base, "detection_corpus.json")))
                != self.corpus_raw
            ):
                errors.append("Manifeste du corpus modifié")
            for kind, name in (("sigma", "regle_sigma.yml"), ("yara", "regle_yara.yar")):
                result = self.tests.get(kind, {})
                if not result.get("test_concluant") or not (
                    result.get("test_reussi") if kind == "sigma" else result.get("verdict") == "OK"
                ):
                    errors.append(f"Test {kind} non réussi")
                if result.get("regle_sha256") != digest(read_bytes(self.output, name)):
                    errors.append(f"Règle {kind} différente de la règle testée")
                if kind == "sigma":
                    current = digest(
                        read_bytes(self.base / "incident", "edr_events.jsonl")
                        + canonical(self.corpus["sigma"]).encode()
                    )
                else:
                    hashes = {
                        k + "/" + n: digest(
                            read_bytes(
                                self.base
                                / ("incident" if k == "malveillants" else "benign_samples"),
                                n,
                            )
                        )
                        for k in ("malveillants", "benins")
                        for n in self.corpus["yara"][k]
                    }
                    current = digest(canonical(hashes).encode())
                if result.get("corpus_sha256") != current:
                    errors.append(f"Corpus {kind} différent du corpus testé")
        except (OSError, ValueError, KeyError):
            errors.append("Règle/corpus absent ou inaccessible")
        if self.decision:
            if self.decision["decision"] == "acceptee" and not self.protocol:
                errors.append("Protocole approuvé absent")
            if self.decision["decision"] == "refusee" and self.protocol:
                errors.append("Protocole interdit après refus")
        if not self.audit.valid():
            errors.append("Journal altéré")
        if require_report and "rapport_incident.md" not in self.artifacts:
            errors.append("Rapport absent")
        return list(dict.fromkeys(errors))

    def render_report(self, errors):
        """Assembler le rapport à partir des livrables vérifiés."""
        render_report(self, errors)

    def stage_tools(self):
        """Outils clos sur la session, sérialisés, aucune mutation de phase disponible."""
        blocked = self.dependency_issues(self.stage)
        if blocked:
            raise ValueError("Phase bloquée : " + "; ".join(blocked))

        def list_evidence() -> dict:
            """Lister les preuves, empreintes, lignes et couverture de lecture."""
            return {
                f: {
                    "sha256": self.evidence.hashes[f],
                    "lignes": len(lines),
                    "lignes_lues": len(self.evidence.covered[f]),
                }
                for f, lines in self.evidence.content.items()
            }

        def read_evidence(
            fichier: str, debut: int | None = None, limite: int = 100, offset: int | None = None
        ) -> dict:
            """Lire une page (1–200 lignes). debut commence à 1 ; offset à 0.

            Utiliser debut OU offset, jamais les deux. Sans aucun des deux, lire
            depuis la ligne 1. Suivre lecture_suivante pour les lignes non lues.
            """
            if debut is not None and offset is not None:
                raise ValueError(
                    "Pagination ambiguë : utiliser debut (à partir de 1) OU offset (à partir de 0), jamais les deux"
                )
            if offset is not None and offset < 0:
                raise ValueError("offset doit être positif ou nul (0 désigne la ligne 1)")
            first = offset + 1 if offset is not None else (1 if debut is None else debut)
            return self.evidence.page(fichier, first, limite)

        def verify_ioc(value: str) -> dict:
            """Trouver toutes les occurrences exactes d'un IOC candidat dans les preuves."""
            return self.verify(value)

        def decode_evidence(fichier: str, ligne: int, encoded: str) -> dict:
            """Décoder une chaîne Base64 prouvée à la ligne indiquée, conserver sa provenance."""
            return self.decode(fichier, ligne, encoded)

        def save_analysis(analysis: Analysis) -> str:
            """Enregistrer constats, qualifications alerte_web/alerte_poste, lien et injections."""
            return self.save_analysis(analysis)

        def save_iocs(iocs: list[IOC]) -> str:
            """Enregistrer les IOC après vérification des occurrences et constats associés."""
            return self.save_iocs(iocs)

        def check_mitre(technique_id: str) -> dict:
            """Vérifier nom, description, tactiques et validité dans le snapshot officiel."""
            return self.check_mitre(technique_id)

        def search_mitre(query: str) -> list[dict]:
            """Chercher les descriptions officielles (mots-clés anglais), cinq résultats maximum."""
            if not self.reference:
                raise ValueError("Référentiel indisponible")
            return self.reference.search(query)

        def save_mitre(associations: list[Mapping]) -> str:
            """Enregistrer les techniques vérifiées avec constats et justifications."""
            return self.save_mappings(associations)

        def validate_sigma(rule_yaml: str) -> dict:
            """Tester UNE règle Sigma windows/process_creation et enregistrer les résultats exacts."""
            return self.test_rule("sigma", rule_yaml)

        def test_yara(rule_text: str) -> dict:
            """Compiler et tester YARA sans inclusion externe, en processus borné."""
            return self.test_rule("yara", rule_text)

        def propose_containment(proposal: Proposal) -> str:
            """Enregistrer UNE proposition consolidée ; aucune approbation ni exécution par cet outil."""
            return self.propose(proposal)

        def save_protocol(protocol: Protocol) -> str:
            """Enregistrer un protocole manuel couvrant exactement les actions/cibles approuvées."""
            return self.save_protocol(protocol)

        def save_report_summary(summary: ReportSummary) -> str:
            """Enregistrer la synthèse sourcée ; le harness assemble ensuite le rapport final."""
            return self.save_summary(summary)

        def read_artifact(name: str) -> str:
            """Relire un livrable déjà enregistré dans la session, sans accès aux autres fichiers."""
            if name not in self.artifacts:
                raise ValueError("Livrable inconnu")
            return read_bytes(self.output, name).decode()

        phase = {
            "preuves": [save_analysis],
            "ioc": [verify_ioc, decode_evidence, save_iocs],
            "mitre": [search_mitre, check_mitre, save_mitre],
            "regles": [validate_sigma, test_yara],
            "confinement": [propose_containment],
            "protocole": [save_protocol],
            "rapport": [save_report_summary],
        }[self.stage]
        functions = [list_evidence, read_evidence, read_artifact] + phase
        expected_stage = self.stage
        result = []
        for fn in functions:

            def wrapper(*args, _fn=fn, **kwargs):
                with self.lock:
                    try:
                        self.require(expected_stage)
                        return _fn(*args, **kwargs)
                    except (ValueError, OSError, KeyError, TypeError) as exc:
                        feedback = self.feedback.reject(_fn.__name__, exc, expected_stage)
                        raise ToolException(feedback) from exc

            spec = StructuredTool.from_function(fn)
            # Ne jamais ignorer un argument inconnu : ce comportement a fait
            # relire la page 1 lorsque le modèle transmettait offset.
            spec.args_schema = create_model(
                f"{fn.__name__}StrictArgs",
                __base__=spec.args_schema,
                __config__=ConfigDict(extra="forbid"),
            )
            spec.func = wrapper
            spec.handle_tool_error = True
            spec.handle_validation_error = lambda exc, name=fn.__name__: self.feedback.reject(
                name, exc, expected_stage
            )
            result.append(spec)
        utc_tool = to_utc.model_copy()
        utc_tool.args_schema = create_model(
            "ToUtcStrictArgs", __base__=utc_tool.args_schema, __config__=ConfigDict(extra="forbid")
        )
        utc_tool.handle_validation_error = lambda exc: self.feedback.reject(
            "to_utc", exc, expected_stage
        )
        result.append(utc_tool)
        return result
