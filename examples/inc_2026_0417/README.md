# Cas pédagogique INC-2026-0417

Ce dossier regroupe les entrées de l’analyse et les données utilisées pour tester les détections.

| Élément | Contenu |
|---|---|
| [incident/](incident/) | Ticket, journaux web/applicatifs, événements EDR et copie texte du script PowerShell |
| [benign_samples/](benign_samples/) | Six scripts de référence pour les négatifs YARA |
| [detection_corpus.json](detection_corpus.json) | Positif YARA, événement positif Sigma et négatifs annotés |

Le corpus est fourni pour une analyse statique. Le harness lit les fichiers et compile les règles ; il ne lance pas les scripts. La copie PowerShell doit être interprétée avec ses commentaires : certaines fonctions sont désactivées, tandis que le code de bypass AMSI reste hors commentaire.

Pour un autre cas, fournir la même structure et le sélectionner avec `--case-dir`. Les qualifications métier restent adaptées aux deux alertes du TD ; une généralisation à d’autres incidents demande de faire évoluer les contrats.
