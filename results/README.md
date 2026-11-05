# Résultats historiques de l’évaluation

Ces dossiers contiennent les sorties originales utilisées pour comparer les itérations du harness. Les fichiers sont conservés à l’octet près, y compris les rapports erronés, les essais et les journaux d’audit. Les nouvelles exécutions utilisent `artifacts/`.

| Version | Dossier | Ancien emplacement |
|---|---|---|
| V1 — Prototype | [v1_prototype/](v1_prototype/) | `output_agentv0/`, puis `resultats_v1_prototype/` |
| V2 — Agent outillé | [v2_agent_outille/](v2_agent_outille/) | `output_agentv1/`, puis `resultats_v2_agent_outille/` |
| V3 — Harness structuré | [v3_harness_structure/](v3_harness_structure/) | `output1/`, puis `resultats_v3_harness_structure/` |
| V4 — Validation des détections | [v4_validation_detection/](v4_validation_detection/) | `output2/`, puis `resultats_v4_validation_detection/` |
| V5 — Validation humaine | [v5_validation_humaine/](v5_validation_humaine/) | `output/`, puis `resultats_v5_validation_humaine/` |
| Runs complémentaires | [archives/](archives/) | `runs/` |

Les chemins présents dans les journaux, anciens rapports et analyses critiques reflètent leur contexte de génération. Certains liens historiques peuvent donc désigner l’ancienne arborescence. Leur texte reste conservé ; la navigation actuelle passe par ce document et les analyses de `docs/`.

Le [manifeste d’intégrité](manifest_integrite.json) contient les SHA-256 des 103 fichiers historiques. Depuis la racine du dépôt :

```bash
python -m scripts.verifier_archives
```

Pour lire l’évaluation : [comparaison](../docs/comparaison_versions.md), [vérifications des règles](../docs/comparaison_verifications.json) et [retour d’expérience](../docs/retour_experience.md).
