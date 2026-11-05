"""Budgets partagés et diagnostic d'exécution, sans outil d'exécution de code."""

from __future__ import annotations

import json
from collections import deque
from threading import Lock

from langchain.agents.middleware import AgentMiddleware
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage

READONLY_TOOLS = frozenset(
    {
        "verify_ioc",
        "to_utc",
        "decode_powershell_b64",
        "check_mitre",
        "search_mitre",
        "read_evidence",
        "list_evidence",
        "read_artifact",
    }
)


def deduplicate_readonly_calls(message: AIMessage) -> AIMessage:
    """Normalise un seul lot de tool_calls, sans cache entre réponses LLM."""
    seen, calls, removed = {}, [], []
    for call in message.tool_calls:
        name = call["name"]
        signature = (name, json.dumps(call["args"], sort_keys=True, ensure_ascii=False))
        if name in READONLY_TOOLS and signature in seen:
            removed.append(
                {
                    "name": name,
                    "removed_id": call["id"],
                    "retained_id": seen[signature],
                }
            )
            continue
        if name in READONLY_TOOLS:
            seen[signature] = call["id"]
        calls.append(call)
    if not removed:
        return message
    # Même ID de message : le reducer LangGraph remplace la réponse, sans ajouter
    # un second message assistant qui laisserait des tool_call_id sans réponse.
    return message.model_copy(
        update={
            "tool_calls": calls,
            "response_metadata": {
                **message.response_metadata,
                "td3_deduplicated_tool_calls": removed,
            },
        }
    )


class DeduplicateReadonlyToolCalls(AgentMiddleware):
    """Évite d'exécuter plusieurs fois une lecture identique dans un même lot."""

    def after_model(self, state, runtime):
        message = state["messages"][-1]
        if not isinstance(message, AIMessage):
            return None
        normalised = deduplicate_readonly_calls(message)
        if normalised is message:
            return None
        removed = normalised.response_metadata["td3_deduplicated_tool_calls"]
        print(
            f"[i] {len(removed)} appel(s) de lecture dupliqué(s) regroupé(s) dans cette réponse LLM",
            flush=True,
        )
        return {"messages": [normalised]}

    async def aafter_model(self, state, runtime):
        return self.after_model(state, runtime)


class ExecutionLimitError(RuntimeError):
    """L'exécution doit s'arrêter plutôt que poursuivre une boucle."""


def graph_step_limit(model_call_limit: int) -> int:
    """Laisser passer les nœuds internes avant d'atteindre le budget LLM."""
    if model_call_limit < 1:
        raise ValueError("TD3_RUN_LIMIT doit être supérieur à zéro")
    return max(400, 16 * (model_call_limit + 1))


class ExecutionMonitor(BaseCallbackHandler):
    # Les exceptions des callbacks sont ignorées par défaut par LangChain.
    raise_error = True
    run_inline = True

    def __init__(self, model_call_limit: int, repeat_limit: int = 4, *, progress=print):
        if model_call_limit < 1 or repeat_limit < 2:
            raise ValueError("Budget LLM >= 1 et limite de répétition >= 2 requis")
        self.model_call_limit = model_call_limit
        self.repeat_limit = repeat_limit
        self.model_calls = 0
        self._last_tool = None
        self._repeats = 0
        self._tools = deque(maxlen=20)
        self._stop_reason = None
        self._first_stop_reason = None
        self._lock = Lock()
        self._progress = progress
        self._analysis_limit = model_call_limit
        self._report_mode = False

    def reserve_report(self, calls: int = 10):
        self._analysis_limit = max(1, self.model_call_limit - calls)

    def begin_report(self):
        # Le compteur total reste inchangé. Seule la réserve de clôture est libérée.
        with self._lock:
            self._report_mode = True
            self._stop_reason = None
            self._last_tool, self._repeats = None, 0

    def on_chat_model_start(self, serialized, messages, **kwargs):
        # Le même callback est transmis aux sous-agents et aux reprises humaines.
        with self._lock:
            if self._stop_reason:
                raise ExecutionLimitError(self._stop_reason)
            limit = self.model_call_limit if self._report_mode else self._analysis_limit
            if self.model_calls >= limit:
                self._stop_reason = f"Budget de {'clôture' if self._report_mode else 'travail'} atteint ({limit} appels sur {self.model_call_limit} au total) ; analyse incomplète."
                self._first_stop_reason = self._first_stop_reason or self._stop_reason
                raise ExecutionLimitError(self._stop_reason)
            self.model_calls += 1
            count = self.model_calls
        self._progress(f"[llm] appel {count}/{self.model_call_limit}", flush=True)

    def on_tool_start(self, serialized, input_str, *, inputs=None, **kwargs):
        name = (serialized or {}).get("name", "outil")
        if inputs is None:
            try:
                inputs = json.loads(input_str)
            except (ValueError, TypeError):
                inputs = input_str
        arguments = json.dumps(inputs, ensure_ascii=False, sort_keys=True, default=str)
        signature = (name, arguments)
        with self._lock:
            if self._stop_reason:
                raise ExecutionLimitError(self._stop_reason)
            self._repeats = self._repeats + 1 if signature == self._last_tool else 1
            self._last_tool = signature
            # Pas de messages LLM ni de résultats d'outils ; arguments bornés en taille.
            self._tools.append({"outil": name, "arguments": arguments[:1000]})
            if self._repeats >= self.repeat_limit:
                self._stop_reason = (
                    f"Boucle détectée : {name} appelé {self._repeats} fois de suite "
                    "avec les mêmes arguments ; analyse incomplète."
                )
                self._first_stop_reason = self._first_stop_reason or self._stop_reason
                raise ExecutionLimitError(self._stop_reason)
        self._progress(f"[outil] {name}", flush=True)

    def snapshot(self):
        with self._lock:
            return {
                "appels_llm": self.model_calls,
                "budget_llm": self.model_call_limit,
                "limite_repetition": self.repeat_limit,
                "derniers_outils": list(self._tools),
                "raison_arret": self._first_stop_reason or self._stop_reason,
            }
