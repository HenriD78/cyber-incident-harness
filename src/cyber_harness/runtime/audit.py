"""Journal local append-only du point de vue du modèle, chaîné et corrélé."""

import json
import os
import re
from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage

from cyber_harness.evidence import canonical, digest, safe_path
from cyber_harness.runtime.diagnostics import response_diagnostic


def redact(value):
    if isinstance(value, dict):
        return {
            k: "[MASQUÉ]"
            if (
                k in {"thinking", "reasoning_content"}
                or (
                    k not in {"input_tokens", "output_tokens", "total_tokens"}
                    and re.search(r"api.?key|password|token|secret|authorization", str(k), re.I)
                )
            )
            else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if not isinstance(value, (str, int, float, bool, type(None))):
        return redact(str(value))
    if isinstance(value, str):
        for name, secret in os.environ.items():
            if re.search(r"API_KEY|TOKEN|SECRET|PASSWORD", name) and len(secret) >= 8:
                value = value.replace(secret, "[MASQUÉ]")
    return value


class AuditLog(BaseCallbackHandler):
    raise_error = True
    run_inline = True

    def __init__(self, root, thread_id):
        self.root, self.thread_id = root, thread_id
        self.lock = RLock()
        self.previous = "0" * 64
        self.count = 0
        self.model_context = {}
        root.mkdir(parents=True, exist_ok=True)
        path = safe_path(root, "audit.jsonl")
        # Un nouveau run ne doit jamais reprendre implicitement un ancien journal.
        with path.open("x", encoding="utf-8"):
            pass

    def event(self, kind, payload, run_id=None, parent_run_id=None):
        with self.lock:
            record = {
                "id": str(uuid4()),
                "sequence": self.count,
                "type": kind,
                "thread_id": self.thread_id,
                "run_id": str(run_id or self.thread_id),
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
                "utc": datetime.now(timezone.utc).isoformat(),
                "precedent_sha256": self.previous,
                "donnees": redact(payload),
            }
            record["sha256"] = digest(canonical(record).encode())
            path = safe_path(self.root, "audit.jsonl")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "a", encoding="utf-8") as stream:
                stream.write(canonical(record) + "\n")
                stream.flush()
            self.previous, self.count = record["sha256"], self.count + 1
            return record["id"]

    def valid(self):
        try:
            previous, count = "0" * 64, 0
            for line in safe_path(self.root, "audit.jsonl").read_text().splitlines():
                event = json.loads(line)
                sha = event.pop("sha256")
                if (
                    event["sequence"] != count
                    or event["precedent_sha256"] != previous
                    or digest(canonical(event).encode()) != sha
                ):
                    return False
                previous, count = sha, count + 1
            return previous == self.previous and count == self.count
        except (OSError, ValueError, KeyError):
            return False

    def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, **kwargs):
        metadata = kwargs.get("metadata") or {}
        with self.lock:
            self.model_context[str(run_id)] = {
                k: metadata[k] for k in ("phase", "invocation_phase", "modele") if k in metadata
            }
        self.event(
            "llm_entree",
            [[m.model_dump() for m in group] for group in messages],
            run_id,
            parent_run_id,
        )

    def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs):
        payload = response.model_dump()
        with self.lock:
            context = self.model_context.pop(str(run_id), {})
        # Pydantic sérialise autrement les sous-classes comme BaseMessage et perd
        # tool_calls/invalid_tool_calls/usage_metadata dans LLMResult.model_dump().
        for group, dumped in zip(response.generations, payload["generations"]):
            for generation, item in zip(group, dumped):
                message = getattr(generation, "message", None)
                if message is not None:
                    item["message"] = message.model_dump()
                if isinstance(message, AIMessage):
                    self.event(
                        "diagnostic_reponse_modele",
                        {**context, **response_diagnostic(message)},
                        run_id,
                        parent_run_id,
                    )
        self.event("llm_sortie", payload, run_id, parent_run_id)

    def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        with self.lock:
            context = self.model_context.pop(str(run_id), {})
        self.event(
            "diagnostic_erreur_modele",
            {**context, "type_erreur": type(error).__name__},
            run_id,
            parent_run_id,
        )
        self.event("llm_erreur", str(error), run_id, parent_run_id)

    def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, **kwargs):
        self.event(
            "outil_entree",
            {"nom": serialized.get("name"), "arguments": input_str},
            run_id,
            parent_run_id,
        )

    def on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs):
        self.event(
            "outil_sortie",
            output.model_dump() if hasattr(output, "model_dump") else output,
            run_id,
            parent_run_id,
        )

    def on_tool_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self.event("outil_erreur", str(error), run_id, parent_run_id)
