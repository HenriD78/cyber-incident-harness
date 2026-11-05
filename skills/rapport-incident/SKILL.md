---
name: rapport-incident
description: Clôturer l'analyse avec une synthèse sourcée ; le harness assemble le rapport final.
---
# Rapport final

1. Relire les livrables disponibles via read_artifact : analyse, IOC, MITRE, résultats
   des tests, proposition, décision humaine et protocole éventuel.
2. Appeler `save_report_summary(summary)` avec resume (5 lignes environ), constat_ids
   qui soutiennent ce résumé, et limites. Mentionner le lien prouvé ou non entre les alertes.
3. Le harness rédige ensuite rapport_incident.md en ajoutant chronologie et statuts,
   IOC et références, mapping MITRE, résultats EXACTS des tests et empreintes,
   proposition et décision humaine, lien vers le protocole accepté, injections et limites.
4. Après refus, constater ce refus, sans nouvelle proposition ni protocole.
5. Sans source, écrire « non vérifié ». Ne jamais inventer une réussite de test,
   une action exécutée, une approbation ou un impact. Terminer après l'enregistrement.
6. `constat_ids` contient uniquement les IDs C1, C2… présents dans analyse.json et
   rappelés dans le contexte de phase. Aucun hash, nom de fichier ou identifiant de
   dérivation n'est un identifiant de constat. `limites` est une liste de chaînes.
   En cas de refus de l'outil, corriger avec les IDs disponibles au lieu d'en deviner.
   Si l'analyse n'a jamais été enregistrée, l'hôte produit le rapport de secours
   directement : aucune synthèse LLM n'est demandée dans ce cas.
