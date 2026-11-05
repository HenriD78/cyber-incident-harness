"""Diagnostic du transport Ollama et récupération sans interpréter le raisonnement."""

import json
from hashlib import sha256
from uuid import uuid4

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langchain_ollama import ChatOllama


class TransportSummary:
    """Ne conserver ni le contenu brut ni le texte de thinking."""

    def __init__(self, *, stream, reasoning):
        self.data = {
            "stream": stream,
            "reasoning_demande": reasoning,
            "fragments": 0,
            "caracteres_content": 0,
            "content_non_blanc": False,
            "caracteres_thinking": 0,
            "appels_outils_bruts": 0,
        }

    def observe(self, part):
        if isinstance(part, str):
            return part
        self.data["fragments"] += 1
        message = part.get("message") or {}
        content = message.get("content") or ""
        self.data["caracteres_content"] += len(content)
        self.data["content_non_blanc"] |= bool(content.strip())
        self.data["caracteres_thinking"] += len(message.get("thinking") or "")
        self.data["appels_outils_bruts"] += len(message.get("tool_calls") or [])
        # L'adaptateur conserve les métadonnées du dernier fragment uniquement.
        if part.get("done"):
            return {**dict(part), "td3_transport": dict(self.data)}
        return part


class DiagnosticChatOllama(ChatOllama):
    """Instrumenter avant la conversion LangChain, sans appel réseau supplémentaire."""

    def _create_chat_stream(self, messages, stop=None, **kwargs):
        summary = TransportSummary(
            stream=kwargs.get("stream", True), reasoning=kwargs.get("reasoning", self.reasoning)
        )
        for part in super()._create_chat_stream(messages, stop, **kwargs):
            yield summary.observe(part)

    async def _acreate_chat_stream(self, messages, stop=None, **kwargs):
        summary = TransportSummary(
            stream=kwargs.get("stream", True), reasoning=kwargs.get("reasoning", self.reasoning)
        )
        async for part in super()._acreate_chat_stream(messages, stop, **kwargs):
            yield summary.observe(part)


def response_diagnostic(message):
    """Séparer le symptôme observé de la cause, inconnue sans métadonnées brutes."""
    metadata = message.response_metadata
    raw = metadata.get("td3_transport")
    text = bool(message.text.strip())
    calls = len(message.tool_calls)
    invalid = len(message.invalid_tool_calls)
    if metadata.get("td3_json_error"):
        category = "json_transport_invalide"
    elif invalid:
        category = "appel_outil_malforme"
    elif calls or text:
        category = "exploitable"
    elif raw and (raw["content_non_blanc"] or raw["appels_outils_bruts"]):
        category = "perte_conversion"
    elif (raw and raw["caracteres_thinking"]) or message.additional_kwargs.get("reasoning_content"):
        category = "raisonnement_seul"
    elif raw:
        category = "reponse_fournisseur_vide"
    else:
        category = "reponse_vide_cause_indeterminee"
    return {
        "categorie": category,
        "texte_present": text,
        "erreur_transport_json": metadata.get("td3_json_error"),
        "appels_outils_valides": calls,
        "appels_outils_invalides": invalid,
        "transport": raw,
        **{
            k: metadata.get(k)
            for k in ("model", "done_reason", "eval_count", "prompt_eval_count", "total_duration")
        },
    }


def parse_writer_envelope(content, allowed):
    """Un seul objet JSON strict ; aucun code, texte libre ou outil hors liste."""
    if len(content) > 1_000_000:
        raise ValueError("Réponse JSON trop volumineuse")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Clé JSON dupliquée")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("Constante JSON non standard interdite")

    value = json.loads(content, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(value, dict) or set(value) != {"tool", "arguments"}:
        raise ValueError("Objet attendu : tool et arguments uniquement")
    if not isinstance(value["tool"], str) or value["tool"] not in allowed:
        raise ValueError("Outil absent des outils d'enregistrement autorisés dans cette phase")
    if not isinstance(value["arguments"], dict):
        raise ValueError("arguments doit être un objet JSON")
    return value


class RecoverEmptyModelResponse(AgentMiddleware):
    """Changer de mode au prochain appel, dans les budgets de l'orchestrateur.

    Une instance par phase séquentielle ; aucun retry caché dans le middleware.
    """

    def __init__(self, writer_tools=(), *, audit=None, phase=None, phase_complete=lambda: False):
        self.empty_responses = 0
        self.writers = {
            tool.name: convert_to_openai_tool(tool)["function"] for tool in writer_tools
        }
        self.audit, self.phase = audit, phase
        self.phase_complete = phase_complete

    def json_mode(self, request):
        return (
            self.empty_responses >= 2
            and bool(self.writers)
            and isinstance(request.model, ChatOllama)
        )

    def recovery_request(self, request):
        if not self.empty_responses or not isinstance(request.model, ChatOllama):
            return request
        updates = {
            "model_settings": {**request.model_settings, "stream": False, "reasoning": False}
        }
        if self.json_mode(request):
            if self.phase_complete():
                return request.override(
                    **updates,
                    tools=[],
                    messages=[
                        *request.messages,
                        HumanMessage(
                            content="Les livrables de cette phase ont été enregistrés et validés par l'hôte. "
                            "Termine la phase en répondant FIN, sans nouvel appel d'outil."
                        ),
                    ],
                )
            instruction = (
                "Récupération du transport : les appels d'outils natifs ont renvoyé du vide. "
                "Réponds uniquement par un objet JSON valide, sans Markdown, de la forme "
                '{"tool":"nom_autorisé","arguments":{...}}. '
                "Choisis un seul outil parmi les schémas suivants, avec ses arguments complets. "
                "Utilise les preuves déjà lues et les références exactes ; distingue les observations, "
                "tentatives bloquées et capacités du script. N'affirme pas qu'une attaque a réussi "
                "sans preuve. N'invente aucun fait, référence ou accord humain. Ce JSON est une "
                "demande : l'hôte validera les arguments et l'outil avant tout enregistrement. "
                "Ne prétends pas avoir enregistré un fichier. Schémas : "
                + json.dumps(list(self.writers.values()), ensure_ascii=False)
            )
            updates.update(
                tools=[], messages=[*request.messages, HumanMessage(content=instruction)]
            )
        return request.override(**updates)

    def decode_response(self, response):
        # Ne convertir que le texte JSON de ce mode explicite. Le ToolNode et les
        # outils typés existants restent responsables de toute validation métier.
        messages = []
        for message in response.result:
            if not isinstance(message, AIMessage):
                messages.append(message)
                continue
            if (
                not message.text.strip()
                and not message.tool_calls
                and not message.invalid_tool_calls
            ):
                messages.append(message)
                continue
            if self.phase_complete() and not message.tool_calls and not message.invalid_tool_calls:
                messages.append(message)
                continue
            try:
                if message.tool_calls or message.invalid_tool_calls:
                    raise ValueError("Appel natif inattendu en mode JSON texte")
                envelope = parse_writer_envelope(message.text, self.writers)
                call = {
                    "name": envelope["tool"],
                    "args": envelope["arguments"],
                    "id": "json-" + uuid4().hex,
                    "type": "tool_call",
                }
                event = {
                    "statut": "converti",
                    "outil": call["name"],
                    "enveloppe_sha256": sha256(message.text.encode()).hexdigest(),
                }
                message = message.model_copy(
                    update={
                        "content": "",
                        "tool_calls": [call],
                        "response_metadata": {
                            **message.response_metadata,
                            "td3_json_tool": call["name"],
                        },
                    }
                )
            except (ValueError, TypeError, RecursionError) as exc:
                error = str(exc)[:300]
                event = {"statut": "refuse", "raison": error}
                message = message.model_copy(
                    update={
                        "tool_calls": [],
                        "invalid_tool_calls": [],
                        "response_metadata": {**message.response_metadata, "td3_json_error": error},
                    }
                )
            if self.audit:
                self.audit.event(
                    "transport_json", {"phase": self.phase, "message_id": message.id, **event}
                )
            messages.append(message)
        # ModelResponse est une dataclass ; ne pas perdre structured_response.
        from dataclasses import replace

        return replace(response, result=messages)

    def wrap_model_call(self, request, handler):
        json_mode = self.json_mode(request)
        response = handler(self.recovery_request(request))
        return self.decode_response(response) if json_mode else response

    async def awrap_model_call(self, request, handler):
        json_mode = self.json_mode(request)
        response = await handler(self.recovery_request(request))
        return self.decode_response(response) if json_mode else response

    def after_model(self, state, runtime):
        message = state["messages"][-1]
        if isinstance(message, AIMessage) and not message.text.strip() and not message.tool_calls:
            self.empty_responses += 1

    async def aafter_model(self, state, runtime):
        return self.after_model(state, runtime)
