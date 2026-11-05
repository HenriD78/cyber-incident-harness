"""Capabilities de l'agent : skills en lecture seule et outils métier de la phase."""

from pathlib import Path

from deepagents.backends import FilesystemBackend
from deepagents.backends.protocol import DeleteResult, EditResult, WriteResult
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

from cyber_harness.evidence import safe_path


class SkillsBackend(FilesystemBackend):
    def _resolve_path(self, key):
        if key.strip("/") == "":
            if Path(self.cwd).is_symlink():
                raise ValueError("Racine skills symbolique interdite")
            return Path(self.cwd)
        return safe_path(Path(self.cwd), key.lstrip("/"))

    def write(self, *args, **kwargs):
        return WriteResult(error="permission denied: skills en lecture seule")

    def edit(self, *args, **kwargs):
        return EditResult(error="permission denied: skills en lecture seule")

    def delete(self, *args, **kwargs):
        return DeleteResult(error="permission denied: skills en lecture seule")

    def upload_files(self, *args, **kwargs):
        raise PermissionError("Écriture backend interdite")


class CapabilityBoundary(AgentMiddleware):
    def __init__(self, names):
        self.allowed = frozenset(names) | {"read_file", "ls", "glob", "grep", "write_todos"}

    def wrap_model_call(self, request, handler):
        selected = [
            t
            for t in request.tools
            if (t.get("name") if isinstance(t, dict) else t.name) in self.allowed
        ]
        return handler(request.override(tools=selected))

    async def awrap_model_call(self, request, handler):
        selected = [
            t
            for t in request.tools
            if (t.get("name") if isinstance(t, dict) else t.name) in self.allowed
        ]
        return await handler(request.override(tools=selected))

    def wrap_tool_call(self, request, handler):
        if request.tool_call["name"] not in self.allowed:
            return ToolMessage(
                content="permission denied: capacité interdite dans cette phase",
                tool_call_id=request.tool_call["id"],
                name=request.tool_call["name"],
                status="error",
            )
        return handler(request)

    async def awrap_tool_call(self, request, handler):
        if request.tool_call["name"] not in self.allowed:
            return ToolMessage(
                content="permission denied: capacité interdite dans cette phase",
                tool_call_id=request.tool_call["id"],
                name=request.tool_call["name"],
                status="error",
            )
        return await handler(request)
