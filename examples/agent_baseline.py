"""Prototype sans harness, conservé pour comparaison : python -m examples.agent_baseline."""

import os
from uuid import uuid4

from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_ollama import ChatOllama

from cyber_harness.config import PROJECT_ROOT
from cyber_harness.prompts import SYSTEM_PROMPT_V1


def main():
    model = os.getenv("TD3_MODEL", "nemotron-3-nano:30b-cloud")
    agent = create_deep_agent(
        model=ChatOllama(model=model, temperature=0),
        system_prompt=SYSTEM_PROMPT_V1,
        backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=True),
    )
    thread_id = f"td3-v1-{uuid4()}"
    print(f"[i] thread LangSmith : {thread_id}")
    reponse = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "Traite le ticket /examples/inc_2026_0417/incident/ticket_INC-2026-0417.md",
                }
            ]
        },
        config={
            "run_name": "td3-agent-v1",
            "tags": ["v1", model],
            "metadata": {"version_agent": "v1", "modele": model, "thread_id": thread_id},
        },
    )
    print(reponse["messages"][-1].content)


if __name__ == "__main__":
    main()
