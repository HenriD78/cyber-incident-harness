"""Exporte les traces LangSmith existantes, sans importer ni lancer l'agent."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from langsmith import APIError, Client, Langsmith
from langsmith.schemas import Run
from langsmith.utils import LangSmithError, get_env_var

SECRET_FIELDS = {"api_key", "apikey", "authorization", "x-api-key", "access_token", "password"}
RUN_FIELDS = [
    "ID",
    "NAME",
    "RUN_TYPE",
    "STATUS",
    "START_TIME",
    "END_TIME",
    "ERROR",
    "INPUTS",
    "OUTPUTS",
    "EXTRA",
    "METADATA",
    "EVENTS",
    "PARENT_RUN_IDS",
    "PROJECT_ID",
    "TRACE_ID",
    "DOTTED_ORDER",
    "TAGS",
    "TOTAL_TOKENS",
    "PROMPT_TOKENS",
    "COMPLETION_TOKENS",
    "TOTAL_COST",
    "PROMPT_COST",
    "COMPLETION_COST",
]


class TraceReader:
    """Adaptateur synchrone de l'API v2, sans Client.list_runs déprécié."""

    def __init__(self, client, api=None):
        self.client = client
        base_url = client.api_url.rstrip("/")
        for suffix in ("/api/v1", "/api"):
            if base_url.endswith(suffix):
                base_url = base_url[: -len(suffix)]
                break
        self.api = api or Langsmith(
            api_key=client.api_key,
            tenant_id=str(client.workspace_id) if client.workspace_id else None,
            base_url=base_url,
        )
        self.projects = {}

    def close(self):
        self.api.close()

    def list_runs(self, *, project_name, limit=None, run_ids=None, **filters):
        if project_name not in self.projects:
            self.projects[project_name] = str(
                self.client.read_project(project_name=project_name).id
            )
        query = {
            "project_ids": [self.projects[project_name]],
            "selects": RUN_FIELDS,
            # Sans cette borne, v2 exclut silencieusement les runs de plus de 24 h.
            "min_start_time": datetime(1970, 1, 1, tzinfo=timezone.utc),
            "include_subtree_usage": False,
            "page_size": min(limit, 1000) if limit else 100,
            **filters,
        }
        if run_ids is not None:
            query["ids"] = [str(run_id) for run_id in run_ids]
        # Le SDK installé nomme la méthode query_v2 ; certains SDK la nomment query.
        resource = self.api.runs
        query_runs = getattr(resource, "query", None) or resource.query_v2
        for index, run in enumerate(query_runs(**query)):
            record = json.loads(run.model_dump_json(exclude={"attachments"}))
            record["run_type"] = record["run_type"].lower()
            record["dotted_order"] = record.get("dotted_order") or ""
            ancestors = record.get("parent_run_ids") or []
            record["parent_run_id"] = ancestors[-1] if ancestors else None
            record["session_id"] = record.pop("project_id", None)
            extra = record.get("extra") or {}
            extra["metadata"] = {
                **(extra.get("metadata") or {}),
                **(record.pop("metadata", None) or {}),
            }
            record["extra"] = extra
            yield Run(**record)
            if limit is not None and index + 1 >= limit:
                break


def redact(value, api_key: str | None):
    """Retire la clé utilisée pour l'export et les champs de secrets usuels."""
    if isinstance(value, dict):
        return {
            key: "[MASQUÉ]" if key.lower() in SECRET_FIELDS else redact(item, api_key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, api_key) for item in value]
    if isinstance(value, str) and api_key:
        return value.replace(api_key, "[MASQUÉ]")
    return value


def collect_runs(client, project: str, *, run_id=None, thread_id=None):
    """Récupère toutes les pages et tous les types de spans des traces choisies."""
    if thread_id is not None:
        # json.dumps échappe les guillemets : le thread reste une valeur du filtre.
        selection = {
            "filter": 'and(eq(metadata_key, "thread_id"), '
            f"eq(metadata_value, {json.dumps(thread_id)}))"
        }
    else:
        selection = {"run_ids": [run_id], "limit": 1}
    seeds = list(client.list_runs(project_name=project, **selection))
    if not seeds:
        raise ValueError("Aucune exécution trouvée dans ce projet pour cet identifiant.")
    by_id = {str(run.id): run for run in seeds}
    for trace_id in sorted({str(run.trace_id) for run in seeds}):
        # Aucun limit : le SDK parcourt toutes les pages, y compris les sous-agents.
        for run in client.list_runs(project_name=project, trace_id=trace_id):
            by_id[str(run.id)] = run
    return sorted(by_id.values(), key=lambda run: (run.start_time, str(run.id)))


def build_export(runs, *, project: str, run_id=None, thread_id=None, api_key=None):
    records = []
    for run in runs:
        # Les pièces jointes ne sont pas téléchargées ni exportées.
        excluded = {"attachments", "child_runs"}
        if hasattr(run, "model_dump_json"):
            record = json.loads(run.model_dump_json(exclude=excluded))
        else:
            record = json.loads(run.json(exclude=excluded))
        record["duration_seconds"] = (
            (run.end_time - run.start_time).total_seconds() if run.end_time else None
        )
        records.append(record)
    llm_calls = [record for record in records if record["run_type"] == "llm"]
    known_ids = {record["id"] for record in records}
    missing_parents = sorted(
        {
            record["parent_run_id"]
            for record in records
            if record.get("parent_run_id") and record["parent_run_id"] not in known_ids
        }
    )
    payload = {
        "schema_version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "project": project,
        "selection": {"run_id": str(run_id) if run_id else None, "thread_id": thread_id},
        "trace_ids": sorted({record["trace_id"] for record in records}),
        "root_run_ids": [record["id"] for record in records if not record.get("parent_run_id")],
        "summary": {
            "runs": len(records),
            "llm_calls": len(llm_calls),
            "tool_calls": sum(record["run_type"] == "tool" for record in records),
            "errors": sum(bool(record.get("error")) for record in records),
            "unfinished_runs": sum(not record.get("end_time") for record in records),
            "missing_parent_ids": missing_parents,
            # Compter les seuls spans LLM évite le double comptage des chaînes parentes.
            "reported_llm_tokens": sum(record.get("total_tokens") or 0 for record in llm_calls),
            "llm_calls_without_token_count": sum(
                record.get("total_tokens") is None for record in llm_calls
            ),
        },
        "runs": records,
        "llm_calls": llm_calls,
    }
    return redact(payload, api_key)


def write_export(path: Path, payload: dict) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    # Un export existant ne doit pas être remplacé silencieusement.
    with path.open("x", encoding="utf-8") as stream:
        stream.write(encoded)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--list", action="store_true", help="lister les exécutions racines du projet"
    )
    selection.add_argument("--run-id", type=UUID, help="exporter une trace à partir d'un ID de run")
    selection.add_argument(
        "--thread-id", help="exporter le thread complet, reprises humaines comprises"
    )
    parser.add_argument("--project", default=get_env_var("PROJECT") or "td3-dargent-genot")
    parser.add_argument(
        "--limit", type=int, default=20, help="nombre de racines affichées avec --list"
    )
    parser.add_argument(
        "--output", type=Path, help="fichier JSON à créer (par défaut dans traces/)"
    )
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit doit être supérieur à zéro")
    if args.list and args.output:
        parser.error("--output s'utilise avec --run-id ou --thread-id")

    client = None
    reader = None
    try:
        # Client de lecture uniquement ; aucune instrumentation de l'agent.
        client = Client(auto_batch_tracing=False)
        if client.workspace_id:
            try:
                UUID(str(client.workspace_id))
            except ValueError:
                raise ValueError(
                    "Workspace invalide : utilisez le vrai UUID dans LANGSMITH_WORKSPACE_ID, "
                    "ou retirez la variable si votre clé ne couvre qu'un workspace."
                ) from None
        reader = TraceReader(client)
        if args.list:
            roots = list(
                reader.list_runs(project_name=args.project, is_root=True, limit=args.limit)
            )
            if not roots:
                print(
                    "Aucune trace trouvée. Vérifiez le projet, la région et l'activation du tracing."
                )
                return 1
            for run in sorted(roots, key=lambda run: run.start_time, reverse=True):
                metadata = (run.extra or {}).get("metadata") or {}
                status = "erreur" if run.error else "terminé" if run.end_time else "en cours"
                print(
                    redact(
                        f"{run.id} | {run.start_time.isoformat()} | {run.name} | {status}"
                        f" | thread={metadata.get('thread_id', 'absent')}",
                        client.api_key,
                    )
                )
            return 0

        runs = collect_runs(reader, args.project, run_id=args.run_id, thread_id=args.thread_id)
        payload = build_export(
            runs,
            project=args.project,
            run_id=args.run_id,
            thread_id=args.thread_id,
            api_key=client.api_key,
        )
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        target = args.output or Path("traces") / f"langsmith_{payload['trace_ids'][0]}_{stamp}.json"
        write_export(target, payload)
        summary = payload["summary"]
        print(f"[ok] Export : {target}")
        print(
            f"[i] {summary['runs']} spans, {summary['llm_calls']} appels LLM, {summary['tool_calls']} appels d'outils"
        )
        if summary["unfinished_runs"] or summary["missing_parent_ids"]:
            print(
                "[!] Trace potentiellement partielle : exécution ou ingestion encore en cours. Réexportez après sa fin."
            )
        return 0
    except (LangSmithError, APIError) as exc:
        print(
            "[!] Échec de lecture LangSmith : "
            + redact(str(exc), client.api_key if client else None),
            file=sys.stderr,
        )
        print(
            "Vérifiez la clé avec accès en lecture, le workspace et LANGSMITH_ENDPOINT "
            "(EU : https://eu.api.smith.langchain.com). Une clé de tracing seule ne permet pas l'export.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, OSError) as exc:
        print("[!] " + redact(str(exc), client.api_key if client else None), file=sys.stderr)
        return 1
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    raise SystemExit(main())
