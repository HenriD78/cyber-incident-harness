---
name: mapping-mitre
description: Associer les constats au snapshot officiel MITRE ATT&CK Enterprise.
---
# Mapping MITRE

1. Relire analyse.json et iocs.json. Partir des comportements sourcés, pas d'une liste
   de techniques attendue. Les statuts des constats sont conservés dans le mapping.
2. Utiliser `search_mitre(query)` avec des mots-clés anglais pour chercher dans les
   descriptions officielles ; `check_mitre(technique_id)` pour chaque ID retenu.
3. Comparer le mécanisme décrit par MITRE au constat précis. Justifier cette association.
   Un identifiant existant ne suffit pas à démontrer la technique.
4. Refuser les techniques révoquées/obsolètes. Vérifier le remplaçant avec check_mitre
   et réévaluer son adéquation. Si le référentiel manque, signaler la limite.
5. Appeler `save_mitre(associations)` : liste d'objets {id, constat_ids, justification}.
   Le harness ajoute nom, description, tactiques, version, preuves et statuts exacts.
