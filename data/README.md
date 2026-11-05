# Cache du référentiel MITRE

Le fichier complet `enterprise-attack.json` est téléchargé localement et ignoré par Git :

```bash
python -m scripts.telecharger_mitre
```

Le téléchargement utilise le dépôt officiel `mitre-attack/attack-stix-data`, vérifie la collection et la version, puis remplace atomiquement le cache. Chaque run conserve la version et l’empreinte utilisées dans `referentiel.json`.

Les tests utilisent un extrait réduit dans [tests/fixtures/mitre_minimal.json](../tests/fixtures/mitre_minimal.json). Ils restent exécutables sans ce téléchargement. L’extrait sert aux tests de contrats et de révocation ; il ne remplace pas le référentiel complet pour une investigation.
