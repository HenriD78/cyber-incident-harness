"""Retours d'erreur compacts et exemples de contrats, sans réparer les preuves à la place du modèle."""

from collections import Counter

from pydantic import ValidationError

from cyber_harness.evidence import canonical

MAX_INVALID_CALLS = 3
MAX_PHASE_INVOCATIONS = 3


class PhaseRecoveryLimitError(RuntimeError):
    """Trop d'appels invalides au même outil dans une phase."""


class IncompletePhaseError(RuntimeError):
    """Le modèle a terminé sans enregistrer les livrables attendus."""


class BusinessValidationError(ValueError):
    """Erreurs calculées par l'hôte, avec les éléments exacts à corriger."""

    def __init__(self, errors):
        self.details = errors
        super().__init__(
            "; ".join(f"{e.get('valeur', e['champ'])} : {e['message']}" for e in errors)
        )


class ToolFeedback:
    def __init__(self, session):
        self.session = session
        self.counts = Counter()
        self.last = {}

    def example(self, name):
        s = self.session
        file = next((f for f, lines in s.evidence.content.items() if lines), None)
        if file is None:
            return None
        ref = s.evidence.reference(file, 1)
        ids = [s.analysis.constats[0].id] if s.analysis else ["C1"]
        if s.analysis:
            ref = s.analysis.constats[0].preuves[0].model_dump()
        examples = {
            "to_utc": {"timestamp": "<horodatage exact avec fuseau à copier depuis une preuve>"},
            "read_evidence": next(
                iter(s.evidence.pending_reads()), {"fichier": file, "debut": 1, "limite": 100}
            ),
            "read_artifact": {"name": next(iter(s.artifacts))},
            "save_analysis": {
                "analysis": {
                    "constats": [
                        {
                            "id": "C1",
                            "description": "<constat factuel à justifier>",
                            "statut": "observe",
                            "preuves": [ref],
                            "horodatage_source": None,
                            "utc": None,
                        }
                    ],
                    "qualifications": {
                        key: {"conclusion": "<qualification à justifier>", "constat_ids": ["C1"]}
                        for key in ("alerte_web", "alerte_poste")
                    },
                    "lien_alertes": "<conclusion sur le lien entre les alertes>",
                    "lien_prouve": False,
                    "preuves_lien": [],
                    "injections": [],
                    "limites": [],
                }
            },
            "save_iocs": {
                "iocs": [
                    {
                        "type": "autre",
                        "valeur": "<valeur vérifiée>",
                        "references": [ref],
                        "contexte": "<rôle justifié>",
                        "confiance": "moyenne",
                        "constat_ids": ids,
                        "derivation_id": None,
                    }
                ]
            },
            "save_mitre": {
                "associations": [
                    {
                        "id": "T1059.001",
                        "constat_ids": ids,
                        "justification": "<comportement correspondant à vérifier>",
                    }
                ]
            },
            "propose_containment": {
                "proposal": {
                    "synthese": "<piste consolidée justifiée>",
                    "actions": [
                        {
                            "id": "A1",
                            "action": "<action proposée>",
                            "cible": "<cible exacte vérifiée>",
                            "constat_ids": ids,
                            "preuves": [ref],
                            "justification": "<justification>",
                            "impact_attendu": "<impact>",
                            "risques": "<risques opérationnels>",
                        }
                    ],
                }
            },
            "save_report_summary": {
                "summary": {
                    "resume": "<résumé fondé sur les constats enregistrés>",
                    "constat_ids": ids,
                    "limites": [],
                }
            },
        }
        if s.decision and s.decision["decision"] == "acceptee":
            examples["save_protocol"] = {
                "protocol": {
                    "proposition_sha256": s.decision["proposition_sha256"],
                    "actions": [
                        {
                            "action_id": a.id,
                            "cible": a.cible,
                            "responsable": "<équipe responsable>",
                            **{
                                key: ["<consigne manuelle détaillée>"]
                                for key in (
                                    "prerequis",
                                    "etapes",
                                    "verifications",
                                    "criteres_arret",
                                    "retour_arriere",
                                )
                            },
                        }
                        for a in s.proposal.actions
                    ],
                }
            }
        if name == "propose_containment" and s.iocs:
            # Montrer une valeur réellement vérifiée dont la référence appartient
            # déjà au constat du gabarit, sans inventer une action opérationnelle.
            line = s.evidence.content[ref["fichier"]][ref["ligne"] - 1]
            from cyber_harness.evidence import contains_indicator

            target = next((i.valeur for i in s.iocs if contains_indicator(i.valeur, line)), None)
            if target:
                examples[name]["proposal"]["actions"][0]["cible"] = target
        return examples.get(name)

    def context(self):
        s = self.session
        result = {
            "constats_disponibles": [
                {"id": f.id, "description": f.description} for f in s.analysis.constats
            ]
            if s.analysis
            else [],
            "livrables_disponibles": list(s.artifacts),
            "lectures_restantes": s.evidence.pending_reads(),
        }
        if s.stage == "confinement":
            result["contexte_confinement"] = s.containment_context()
        return result

    def reject(self, name, error, stage):
        s = self.session
        with s.lock:
            s.require(stage)
            key = (stage, name)
            self.counts[key] += 1
            if isinstance(error, ValidationError):
                # Regrouper les erreurs répétées sur les listes : 39 erreurs ne
                # doivent pas masquer la structure à corriger dans un long traceback.
                grouped = Counter(
                    (
                        ".".join("*" if isinstance(p, int) else str(p) for p in e["loc"]),
                        e["msg"],
                        e["type"],
                    )
                    for e in error.errors(
                        include_input=False, include_url=False, include_context=False
                    )
                )
                errors = [
                    {"champ": path, "message": message, "type": kind, "occurrences": count}
                    for (path, message, kind), count in grouped.items()
                ]
                code = "arguments_invalides"
            elif isinstance(error, BusinessValidationError):
                errors, code = error.details, "validation_metier"
            else:
                errors, code = [{"message": str(error)}], "validation_metier"
            payload = {
                "statut": "erreur",
                "outil": name,
                "phase": stage,
                "code": code,
                "erreurs": errors[:15],
                "groupes_erreurs_total": len(errors),
                "appels_invalides": self.counts[key],
                "maximum": MAX_INVALID_CALLS,
                "consigne": "Corriger cet appel avant de terminer la phase. Ne pas inventer de preuve, d'empreinte ou d'identifiant.",
                **self.context(),
            }
            example = self.example(name)
            if example:
                payload["exemple_structure"] = example
                payload["note_exemple"] = (
                    "Gabarit de structure uniquement. Remplacer les textes entre chevrons par des faits vérifiés ; copier les références exactes des outils."
                )
            self.last[stage] = payload
            s.audit.event("outil_invalide", payload)
            print(f"[!] {name} : {code} ({self.counts[key]}/{MAX_INVALID_CALLS})", flush=True)
            if self.counts[key] >= MAX_INVALID_CALLS:
                raise PhaseRecoveryLimitError(
                    f"{name} : {MAX_INVALID_CALLS} appels invalides ; dernier refus : "
                    + "; ".join(
                        (f"{e['valeur']} : " if "valeur" in e else "") + e["message"]
                        for e in errors[:3]
                    )
                )
            return canonical(payload)
