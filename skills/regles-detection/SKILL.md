---
name: regles-detection
description: Produire et tester une règle Sigma comportementale et une règle YARA statique.
---
# Règles et tests

1. Relire analyse.json et mitre.json. Cibler le lancement PowerShell observé, parent
   OUTLOOK.EXE, options ExecutionPolicy Bypass et WindowStyle Hidden.
2. Sigma : `logsource: {product: windows, category: process_creation}` sans service.
   Utiliser Image, ParentImage, CommandLine, User, Computer et les modificateurs chaînes
   endswith/contains/contains|all ; le sous-ensemble pris en charge est vérifié.
   Inclure titre, UUID, statut, description, niveau, faux positifs et tags MITRE vérifiés.
3. Appeler `validate_sigma(rule_yaml)`. Un succès exige test_concluant ET test_reussi,
   donc détection des positifs annotés et absence de faux positifs dans le corpus local.
4. YARA : choisir des caractéristiques propres au script (obfuscation AMSI, chaînes
   distinctives…), éviter une seule cmdlet d'administration. Interdiction des include.
   Appeler `test_yara(rule_text)`. Exiger test_concluant et verdict OK.
5. Quatre tentatives maximum par moteur, imposées par les outils. Corriger les erreurs
   concrètes ; si le test reste impossible, signaler sa limite et terminer la phase.
6. Les destinations et résultats sont gérés par les outils. Ne pas inventer un résultat
   ni modifier une règle après son dernier test. Les performances du corpus local ne
   constituent pas une certification de déploiement SIEM ou de couverture générale.
