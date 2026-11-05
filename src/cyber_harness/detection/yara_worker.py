"""Processus de test uniquement : compile des règles et lit des octets, sans exécuter les échantillons."""

import base64
import json
import sys


def main():
    import yara

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    except (ImportError, ValueError, OSError):
        pass
    request = json.load(sys.stdin)
    try:
        rules = yara.compile(source=request["rule"], includes=False)
        hits = [
            s["name"]
            for s in request["samples"]
            if rules.match(data=base64.b64decode(s["data"]), timeout=2)
        ]
        print(json.dumps({"compile": True, "hits": hits, "test_concluant": True}))
    except yara.Error as exc:
        print(json.dumps({"compile": False, "test_concluant": False, "erreur": str(exc)}))


if __name__ == "__main__":
    main()
