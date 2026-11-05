# Cyber Incident Harness

Agent d’analyse d’incident cyber avec preuves sourcées, détections testées et validation humaine du confinement.

Projet réalisé par **Henri DARGENT et Luka GENOT**, ESILV — Security Use Cases, groupe 2.

Le modèle lit les preuves, extrait les IOC, associe les comportements à MITRE ATT&CK et propose des règles Sigma/YARA. Le harness Python contrôle les phases, vérifie les références, teste les règles et recueille la décision humaine. **Il n’exécute ni les scripts de l’incident ni les actions de confinement.**

## Prise en main

Python **3.11 ou supérieur**. Depuis la racine du dépôt :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m cyber_harness --help
```

L’installation en mode éditable lie le package au dépôt, qui contient les preuves et les procédures. Les dépendances métier sont fixées dans [requirements.txt](requirements.txt) ; les métadonnées et les outils de développement sont définis dans [pyproject.toml](pyproject.toml).

Pour analyser le cas pédagogique, Ollama et l’accès au modèle doivent être configurés :

```bash
python -m scripts.telecharger_mitre
cyber-harness --run-label evaluation
```

`python -m cyber_harness` est équivalent à `cyber-harness`. Le modèle par défaut est `gemma4:31b-cloud` : Ollama est l’interface d’accès, et ce modèle utilise un service distant.

```bash
cyber-harness --model gemma4:31b-cloud --run-limit 200 --repeat-limit 4
```

Les options `--case-dir`, `--skills-dir`, `--mitre-file` et `--output-dir` permettent de choisir les ressources. Les variables `TD3_MODEL`, `TD3_RUN_LIMIT` et `TD3_REPEAT_LIMIT` restent reconnues. [.env.example](.env.example) décrit ces variables ; son contenu n’est pas chargé automatiquement.

## Organisation du dépôt

```text
.
├── src/cyber_harness/             # Package Python installable
│   ├── cli.py                    # Configuration et lancement
│   ├── config.py                 # Chemins et paramètres d’exécution
│   ├── workflow.py               # Agent par phase et orchestration
│   ├── session.py                # État métier, outils typés et validations
│   ├── models.py                 # Contrats Pydantic des livrables
│   ├── evidence.py               # Lecture, pagination, empreintes et décodage
│   ├── mitre.py                  # Référentiel officiel figé par run
│   ├── reporting.py              # Assemblage du rapport
│   ├── tools.py                  # Wrappers pour vérifications unitaires
│   ├── detection/                # Évaluateurs Sigma/YARA et worker borné
│   └── runtime/                  # Audit, capacités, budgets et récupération
├── examples/
│   ├── agent_baseline.py          # Prototype historique sans harness
│   └── inc_2026_0417/             # Preuves, scripts bénins et corpus annoté
├── skills/                       # Six procédures métier en lecture seule
├── tests/                        # Tests hors réseau et fixtures de régression
├── scripts/                      # Maintenance du dépôt et intégrité
├── docs/                         # Architecture, utilisation, comparaison et REX
├── results/                      # Résultats historiques conservés et versionnés
├── data/                         # Cache MITRE téléchargé, ignoré par Git
└── artifacts/                    # Nouvelles sorties locales, ignorées par Git
```

## Fonctionnement

Le parcours suit sept phases : **preuves → IOC → ATT&CK → règles → confinement → protocole → rapport**. Le protocole est produit uniquement après accord humain. Un refus termine le parcours par un rapport, sans nouvelle proposition.

Chaque référence contient un fichier, une ligne et son empreinte SHA-256. Le harness impose la couverture de lecture, vérifie les dépendances et conserve les échecs dans le bilan. Les corrections et appels au modèle sont bornés. Le rapport final utilise les résultats enregistrés.

Les nouvelles exécutions écrivent dans `artifacts/latest/`. Son contenu précédent est déplacé dans `artifacts/runs/`. Le lanceur refuse une sortie qui recouvre les sources, les preuves ou les résultats historiques.

Codes de sortie : `0` pour un parcours validé, y compris après refus humain ; `1` pour un parcours incomplet ; `2` pour une configuration CLI invalide ; `130` pour une interruption humaine.

## Résultats historiques

Les cinq itérations sont dans [results/](results/README.md), séparément des nouvelles exécutions :

| Version | Rapport |
|---|---|
| V1 — Prototype | [Rapport initial](results/v1_prototype/rapport_incident.md) |
| V2 — Agent outillé | [Rapport enrichi](results/v2_agent_outille/rapport_incident.md) |
| V3 — Harness structuré | [Rapport avec contrôles](results/v3_harness_structure/rapport_incident.md) |
| V4 — Validation des détections | [Rapport de validation](results/v4_validation_detection/rapport_incident.md) |
| V5 — Validation humaine | [Rapport avec décision humaine](results/v5_validation_humaine/rapport_incident.md) |

Les autres runs précédemment archivés sont dans `results/archives/`. Les **103 fichiers historiques** ont conservé leur contenu exact, y compris les erreurs des anciennes analyses et les journaux chaînés. Le [manifeste d’intégrité](results/manifest_integrite.json) permet de le vérifier :

```bash
python -m scripts.verifier_archives
```

Ces versions désignent des itérations d’évaluation, indépendantes de la version technique du package et de l’étiquette `--run-label`.

## Vérifications

```bash
python -m unittest discover -s tests -t . -v
ruff check src tests scripts examples
ruff format --check src tests scripts examples
```

Les tests utilisent des faux modèles, des répertoires temporaires et un extrait MITRE embarqué. Ils ne demandent ni clé, ni Ollama, ni téléchargement du référentiel complet. Le workflow [GitHub Actions](.github/workflows/ci.yml) automatise ces contrôles sur Python 3.11 et 3.12 après installation des dépendances.

## Documentation

- [Architecture et frontières de confiance](docs/architecture.md).
- [Guide d’utilisation et diagnostic](docs/guide_utilisation.md).
- [Comparaison qualitative des cinq versions](docs/comparaison_versions.md).
- [Retour d’expérience](docs/retour_experience.md).
- [Contribuer et maintenir le projet](CONTRIBUTING.md).

Le statut « complet » confirme les contrôles du parcours ; la pertinence de l’interprétation et du protocole doit encore être relue par un analyste. Les limites observées et les évolutions envisagées pour la production sont détaillées dans le retour d’expérience.
