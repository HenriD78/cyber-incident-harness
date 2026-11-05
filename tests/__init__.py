"""Tests hors réseau : le modèle et la télémétrie distante sont désactivés."""

import os

for name in (
    "LANGSMITH_TRACING",
    "LANGSMITH_TRACING_V2",
    "LANGCHAIN_TRACING",
    "LANGCHAIN_TRACING_V2",
):
    os.environ[name] = "false"
