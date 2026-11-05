"""Réponse à incident séquentielle, preuves statiques et confinement exclusivement manuel."""

from __future__ import annotations

import json
import time

from deepagents import (
    FilesystemPermission,
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    create_deep_agent,
    register_harness_profile,
)
from langchain.agents.middleware import ModelCallLimitMiddleware
from langchain.agents.middleware.model_call_limit import ModelCallLimitExceededError
from langchain_core.messages import AIMessage
from langgraph.errors import GraphRecursionError

from cyber_harness.evidence import safe_path
from cyber_harness.prompts import SYSTEM_PROMPT_V2
from cyber_harness.runtime.boundaries import CapabilityBoundary, SkillsBackend
from cyber_harness.runtime.control import (
    DeduplicateReadonlyToolCalls,
    ExecutionLimitError,
    ExecutionMonitor,
    graph_step_limit,
)
from cyber_harness.runtime.diagnostics import (
    DiagnosticChatOllama,
    RecoverEmptyModelResponse,
    response_diagnostic,
)
from cyber_harness.runtime.feedback import (
    MAX_PHASE_INVOCATIONS,
    IncompletePhaseError,
    PhaseRecoveryLimitError,
)
from cyber_harness.session import PHASE_WRITERS, PHASES, SKILLS, Session


def build_agent(session: Session, model=None):
    # Le modèle Ollama n'a ni sous-agent généraliste, ni outil shell générique.
    register_harness_profile(
        "ollama",
        HarnessProfile(
            general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
            excluded_tools=frozenset({"execute", "write_file", "edit_file"}),
        ),
    )
    stage_tools = session.stage_tools()
    skills = safe_path(session.skills_dir.parent, session.skills_dir.name)
    agent = create_deep_agent(
        model=model
        if model is not None
        else DiagnosticChatOllama(
            model=session.settings.model,
            temperature=0,
            num_ctx=32768,
            client_kwargs={"timeout": 120},
        ),
        tools=stage_tools,
        system_prompt=SYSTEM_PROMPT_V2,
        backend=SkillsBackend(root_dir=skills, virtual_mode=True),
        skills=["/"],
        subagents=[],
        permissions=[FilesystemPermission(operations=["write"], paths=["/**"], mode="deny")],
        middleware=[
            CapabilityBoundary([t.name for t in stage_tools]),
            RecoverEmptyModelResponse(
                [t for t in stage_tools if t.name in PHASE_WRITERS[session.stage]],
                audit=session.audit,
                phase=session.stage,
                phase_complete=lambda: not session.phase_issues(session.stage),
            ),
            DeduplicateReadonlyToolCalls(),
            ModelCallLimitMiddleware(run_limit=session.settings.run_limit, exit_behavior="error"),
        ],
    )
    return agent


def human_decision(proposal):
    print("\nPROPOSITION DE CONFINEMENT — aucune action ne sera exécutée par l'agent")
    print(json.dumps(proposal.model_dump(), ensure_ascii=False, indent=2))
    while True:
        answer = (
            input("Accepter cette piste et rédiger son protocole manuel ? (o/n) ").strip().lower()
        )
        if answer in {"o", "n"}:
            return answer == "o", "" if answer == "o" else input(
                "Motif du refus (facultatif) : "
            ).strip()
        print("Répondre o ou n ; aucune décision n'a été enregistrée.")


def phase_prompt(session):
    phase = session.stage
    examples = {name: session.feedback.example(name) for name in PHASE_WRITERS[phase]}
    return (
        f"Phase autorisée : {phase}. Lis /{SKILLS[phase]}/SKILL.md, puis réalise uniquement cette phase. "
        "Utilise les outils typés pour enregistrer les résultats. Un appel refusé ne termine pas la phase : "
        "corrige les champs indiqués, puis vérifie que l'enregistrement a réussi. "
        "Les preuves doivent être lues via read_evidence, jamais exécutées. "
        "constat_ids désigne exclusivement les identifiants C1, C2… enregistrés dans analyse.json ; "
        "ni un hash, ni un nom de fichier, ni un identifiant de dérivation. "
        "Contexte vérifié : "
        + json.dumps(session.feedback.context(), ensure_ascii=False)
        + "\nGabarits de structure (remplacer les textes entre chevrons par des faits vérifiés) : "
        + json.dumps({k: v for k, v in examples.items() if v}, ensure_ascii=False)
        + (
            "\nDécision humaine : " + json.dumps(session.decision, ensure_ascii=False)
            if session.decision
            else ""
        )
    )


def invoke_phase(session, agent, config):
    """Conserver l'historique pour une correction bornée si le modèle termine trop tôt."""
    phase = session.stage
    messages = [{"role": "user", "content": phase_prompt(session)}]
    for attempt in range(1, MAX_PHASE_INVOCATIONS + 1):
        session.record_phase(phase, "en_cours", invocations=attempt)
        result = agent.invoke(
            {"messages": messages},
            config={
                **config,
                "run_name": f"td3-{phase}-{attempt}",
                "metadata": {
                    **config.get("metadata", {}),
                    "phase": phase,
                    "invocation_phase": attempt,
                },
            },
        )
        issues = session.phase_issues(phase)
        if not issues:
            return attempt
        last = result["messages"][-1]
        diagnostic = response_diagnostic(last) if isinstance(last, AIMessage) else None
        empty = diagnostic and (
            (not diagnostic["texte_present"] and not diagnostic["appels_outils_valides"])
            or diagnostic["categorie"] == "json_transport_invalide"
        )
        if empty:
            session.audit.event(
                "reponse_inexploitable",
                {"phase": phase, "invocation": attempt, **diagnostic},
                run_id=last.id,
            )
            print(
                f"[!] {phase} : {diagnostic['categorie']} ; aucun résultat exploitable reçu",
                flush=True,
            )
        if attempt == MAX_PHASE_INVOCATIONS or not session.phase_retryable(phase):
            detail = f"Réponse modèle inexploitable ({diagnostic['categorie']}) ; " if empty else ""
            raise IncompletePhaseError(detail + "; ".join(issues))
        correction = {
            "phase": phase,
            "statut": "non_terminee",
            "problemes": issues,
            "relance": attempt + 1,
            "maximum": MAX_PHASE_INVOCATIONS,
            "dernier_refus": session.feedback.last.get(phase),
            "consigne": "Les livrables attendus ne sont pas enregistrés/valides. Corriger dans cette même phase ; ne pas passer à une autre étape.",
            **session.feedback.context(),
        }
        if empty:
            correction.update(
                {
                    "diagnostic_modele": diagnostic,
                    "consigne": "La réponse précédente ne contient aucun résultat exploitable. "
                    "Utilise les preuves déjà lues et appelle explicitement l'outil d'enregistrement "
                    "de cette phase avec des faits et références vérifiés. Ne réponds pas seulement "
                    "par un raisonnement ou une annonce de sauvegarde. Corrige les erreurs de format éventuelles.",
                    "outils_enregistrement": list(PHASE_WRITERS[phase]),
                    "gabarits": {
                        name: session.feedback.example(name) for name in PHASE_WRITERS[phase]
                    },
                }
            )
        session.audit.event("relance_phase", correction)
        print(
            f"[!] {phase} : résultat incomplet, correction {attempt}/{MAX_PHASE_INVOCATIONS - 1}",
            flush=True,
        )
        # Éviter de réinjecter un message assistant vide ; conserver toutes les
        # lectures et tous les échanges d'outils. Le journal conserve l'original.
        history = result["messages"][:-1] if empty else result["messages"]
        messages = [
            *history,
            {"role": "user", "content": json.dumps(correction, ensure_ascii=False)},
        ]


def run_workflow(session, *, model_factory=None, decide=human_decision, monitor=None):
    """Contrôler les prérequis et postconditions ; les erreurs récupérées restent tracées."""
    monitor = monitor or ExecutionMonitor(session.settings.run_limit, session.settings.repeat_limit)
    monitor.reserve_report(min(10, max(1, monitor.model_call_limit // 5)))
    interrupted = False
    exhausted = False
    start = time.monotonic()
    config = {
        "callbacks": [session.audit, monitor],
        "recursion_limit": graph_step_limit(monitor.model_call_limit),
        "tags": ["cyber-harness", session.settings.model],
        "metadata": {"thread_id": session.audit.thread_id, "modele": session.settings.model},
    }
    try:
        for phase in PHASES:
            if phase == "protocole" and (
                not session.decision or session.decision["decision"] != "acceptee"
            ):
                session.record_phase(phase, "ignoree", ["Aucun accord humain : protocole interdit"])
                continue
            if phase == "rapport":
                monitor.begin_report()
                if session.dependency_issues(phase):
                    session.record_phase(
                        phase,
                        "secours",
                        [
                            "Analyse vérifiée indisponible : rapport assemblé par l'hôte sans synthèse LLM"
                        ],
                    )
                    continue
            elif exhausted:
                session.record_phase(
                    phase, "bloquee", ["Limite d'exécution atteinte ; budget réservé à la clôture"]
                )
                continue
            blocked = session.dependency_issues(phase)
            if blocked:
                session.record_phase(phase, "bloquee", blocked)
                print(f"[!] Phase {phase} bloquée : " + "; ".join(blocked), flush=True)
                continue
            session.enter(phase)
            try:
                model = model_factory(phase, session) if model_factory else None
                agent = build_agent(session, model)
                attempts = invoke_phase(session, agent, config)
                if phase == "confinement":
                    accepted, reason = decide(session.proposal)
                    session.decide(accepted, reason)
                session.record_phase(phase, "terminee", invocations=attempts)
            except (ExecutionLimitError, ModelCallLimitExceededError, GraphRecursionError) as exc:
                exhausted = True
                session.record_phase(
                    phase,
                    "echec",
                    [f"Limite atteinte : {exc}"],
                    session.phase_status.get(phase, {}).get("invocations", 0),
                )
                session.audit.event("limite", {"phase": phase, "erreur": str(exc)})
            except (PhaseRecoveryLimitError, IncompletePhaseError) as exc:
                session.record_phase(
                    phase,
                    "echec",
                    [str(exc)],
                    session.phase_status.get(phase, {}).get("invocations", 0),
                )
                print(f"[!] Phase {phase} en échec : {exc}", flush=True)
            except (KeyboardInterrupt, EOFError):
                raise
            except Exception as exc:
                session.record_phase(
                    phase,
                    "echec",
                    [f"{type(exc).__name__} : {exc}"],
                    session.phase_status.get(phase, {}).get("invocations", 0),
                )
                session.audit.event("phase_erreur", {"phase": phase, "erreur": str(exc)})
    except (KeyboardInterrupt, EOFError):
        interrupted = True
        session.errors.append("Interruption humaine ; décision non inférée")
        if session.stage:
            session.record_phase(
                session.stage,
                "echec",
                ["Interruption humaine ; décision non inférée"],
                session.phase_status.get(session.stage, {}).get("invocations", 0),
            )
    finally:
        errors = session.validate()
        session.render_report(errors)
        errors = session.validate(require_report=True)
        status = (
            "incomplet"
            if errors
            else ("cloture_refus" if session.decision["decision"] == "refusee" else "complet")
        )
        session.save(
            "validation_finale.json",
            {"statut": status, "erreurs": errors, "phases": session.phase_status},
        )
        session.save(
            "diagnostic_execution.json",
            {
                "statut": status,
                "thread_id": session.audit.thread_id,
                "modele": session.settings.model,
                "duree_secondes": round(time.monotonic() - start, 2),
                **monitor.snapshot(),
                "preuves_intactes": session.evidence.intact(),
                "sha256_avant": session.evidence.hashes,
                "phases": session.phase_status,
            },
        )
        print(f"[i] {status} — rapport : {session.output / 'rapport_incident.md'}")
    return 130 if interrupted else (1 if errors else 0)
