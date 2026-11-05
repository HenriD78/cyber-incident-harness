**Comparaison qualitative des cinq sorties — INC-2026-0417**

Analyse du 5 novembre 2026, dans l'ordre demandé : `V1 — Prototype` → `V2 — Agent outillé` → `V3 — Harness structuré` → `V4 — Validation des détections` → `V5 — Validation humaine`.

**Verdict : le harness progresse nettement dans le contrôle du parcours, la provenance et la déclaration des échecs. L'amélioration du raisonnement et des détections est plus irrégulière. `V5 — Validation humaine` est la sortie la plus aboutie, mais son statut « COMPLET — contrôles structurels réussis » ne signifie pas que toutes ses conclusions et recommandations sont correctes.**

Les régressions les plus importantes de la dernière itération concernent la couverture des IOC, la spécificité de YARA et la pertinence du confinement du poste. La distinction essentielle pour évaluer ce projet est celle entre un livrable traçable, un livrable qui passe le corpus de test et un livrable pertinent pour l'analyste.

**Méthode et limites de cette comparaison**

La comparaison porte sur les rapports, chronologies, IOC, mappings, règles, tests, propositions, décisions et protocoles présents. Les journaux `audit.jsonl` des trois dernières sorties ont servi à reconstituer les vérifications et refus, notamment les IOC qui n'ont finalement pas été enregistrés. Les preuves ont été relues dans `examples/inc_2026_0417/incident/`. L'analyse critique déjà présente dans `results/v1_prototype/` a été consultée comme document secondaire ; les principaux constats ont été vérifiés à nouveau.

Les cinq empreintes de preuves des manifestes de `V3 — Harness structuré`, `V4 — Validation des détections` et `V5 — Validation humaine` sont identiques et correspondent aux fichiers actuels. Les références structurées de leurs analyses, mappings, IOC, propositions et dérivations ont été contrôlées : fichiers existants, lignes dans les bornes, bonnes empreintes. Aucune référence invalide n'a été trouvée dans ces objets. Les références des IOC finaux contiennent effectivement les valeurs annoncées. Les trois chaînes d'audit sont cohérentes et les règles finales correspondent aux empreintes de leurs derniers tests. L'empreinte de la proposition finale correspond aussi à celle de la décision humaine.

Les règles ont été soumises à nouveau à pySigma et YARA, et aux fonctions locales d'évaluation statique de `tools.py`, sans lancer l'agent. Ces fonctions ont été chargées séparément pour ne pas dépendre de l'installation de LangChain. Les résultats finaux sont reproduits dans [comparaison_verifications.json](comparaison_verifications.json). Des petits exemples bénins construits pour cette comparaison ont aussi été analysés ; ils servent à montrer des contre-exemples, pas à estimer un taux de faux positifs en production. Aucun script PowerShell, téléchargement ou confinement n'a été exécuté.

L'environnement de revalidation disponible contient pySigma **1.5.1**, YARA **4.5.4** et PyYAML **6.0.3**. Le projet déclare pySigma 2.0.2 dans ses dépendances : cette revalidation corrobore les résultats enregistrés, mais ne constitue pas une reproduction à versions de dépendances identiques. Les journaux des runs restent la source des résultats historiques et des nombres de tentatives.

L'ordre des dossiers est celui fourni par l'utilisateur. Leur nom ne suffit pas à identifier le code exact ayant produit chaque run : l'analyse critique existante précise même que le programme de la première sortie était alors nommé `agent_v1.py`. Les trois derniers diagnostics déclarent `gemma4:31b-cloud`, mais une seule sortie par itération ne permet pas d'attribuer chaque différence au seul harness. Le référentiel ATT&CK déclaré passe également de 20.0 dans `V3 — Harness structuré` à 20.1 dans les deux dernières sorties.

**Comparaison d'ensemble**

| Critère | `V1 — Prototype` | `V2 — Agent outillé` | `V3 — Harness structuré` | `V4 — Validation des détections` | `V5 — Validation humaine` |
|---|---|---|---|---|---|
| Lien entre alertes | Lien confirmé et IP d'envoi du courriel inventés | Acteur commun et coordination jugés probables sans preuve | Aucun lien démontré | Aucun lien démontré, mais indépendance formulée trop fortement | Même amélioration, même excès sur l'indépendance |
| Statut des comportements | Confusion entre code, tentative et succès | Persistance présentée comme observée | Séparation explicite des statuts | Séparation maintenue | Constats mieux séparés, conclusions encore trop affirmatives |
| IOC et citations | Valeurs plausibles, aucune provenance précise systématique | Quelques bonnes références, mais plage `app.log:7-22` impossible | Enregistrement refusé, aucun `iocs.json` | Même échec, malgré un décodage utile | IOC enregistrés avec références exactes, mais omissions importantes |
| ATT&CK | Plusieurs noms faux et identifiants révoqués | Erreurs de noms et de pertinence persistantes | Identifiants officiels, certaines associations faibles | Meilleurs choix pour SQLi et AMSI, quelques omissions | Ensemble plus cohérent, mais automatisation non prouvée et perte de précision sur Run/RunOnce |
| Sigma finale | Rejetée par pySigma | Rejetée malgré l'annonce de validation | Test local réussi ; clé YAML dupliquée | Test local réussi ; condition plus large que sa description | Même logique que `V4 — Validation des détections` |
| YARA finale | Syntaxe invalide | Compile et détecte, mais une IP interne seule suffit | Compilation finale en échec après quatre essais | Test local réussi, détection portée par registre + tâche | Test local réussi, mais une seule chaîne générique suffit |
| Confinement et humain | Consigne textuelle et statuts non prouvés | Deux approbations consignées ; rapport contradictoire | Blocage explicite faute d'IOC | Blocage maintenu | Proposition liée à une décision humaine et protocole, mais action/cible incohérentes |

**Ce que les preuves permettent réellement de conclure**

Le volet web montre des scans de chemins sensibles, des requêtes SQLi, un accès réussi au compte `admin` et des exports/téléchargements importants depuis la même IP. Les sources les plus utiles sont [web_access.log](../examples/inc_2026_0417/incident/web_access.log), lignes 8–26, 30–33 et 38–51, ainsi que [app.log](../examples/inc_2026_0417/incident/app.log), lignes 1–10. Il existe donc des éléments forts de compromission applicative et d'exposition de données. En revanche, les journaux ne démontrent pas directement le mécanisme par lequel les identifiants `admin` ont été obtenus. La succession « SQLi puis authentification » ne suffit pas à prouver « la SQLi a volé le mot de passe qui a servi à la connexion ».

Sur le poste, [edr_events.jsonl](../examples/inc_2026_0417/incident/edr_events.jsonl) atteste la création du fichier par Outlook, le lancement de PowerShell, deux requêtes WMI, une résolution DNS en échec, une connexion bloquée et l'isolation déjà effectuée. Le contexte de pièce jointe est aussi explicite dans [le ticket](../examples/inc_2026_0417/incident/ticket_INC-2026-0417.md), lignes 11–13. Cela justifie une qualification sérieuse et une investigation du poste. Cela ne démontre pas une persistance installée, un keylogger actif ou une exfiltration réussie depuis ce poste.

La copie du script distingue plusieurs situations que le rapport doit préserver :

| Élément | Preuve | Conclusion justifiée |
|---|---|---|
| Téléchargement/lancement de charges | `facture_2024-11.ps1.txt:33-51`, bloc commenté | Code présent ; téléchargement réussi non établi |
| Modification Run/RunOnce | `:61-70`, bloc commenté | Persistance décrite, installation non démontrée |
| Enregistrement d'une tâche | `:78-90`, bloc commenté | Création de la tâche non observée |
| Keylogging | `:107-129`, bloc commenté | Code de capture présent, collecte réelle non démontrée |
| Envoi HTTP de données système | `:138-149`, bloc commenté | Code présent ; l'événement réseau fourni est bloqué |
| Tentative de bypass AMSI | `:17-19`, hors commentaire | Code actif dans cette copie, réussite non démontrée par l'EDR |
| Commande Base64 | `:12`, affectation à une variable | Texte encodé présent ; son exécution n'est pas démontrée |

La bannière du script affirmant que toutes les fonctions dangereuses sont désactivées (`:177`) ne doit donc pas être reprise sans analyse. Le bypass AMSI est une exception visible. Les dernières sorties ne l'explicitent pas suffisamment.

Aucune IP source de courriel ni aucun IOC commun ne relie techniquement les deux alertes. La conclusion prudente est « aucun lien démontré avec les preuves disponibles ». Affirmer que les attaques sont indépendantes ou techniquement distinctes va plus loin que ce que l'absence de lien permet de conclure.

**De `V1 — Prototype` à `V2 — Agent outillé` : progrès partiel, fiabilité encore faible**

La première sortie invente une chaîne causale complète : `203.0.113.42` aurait aussi envoyé le courriel de phishing. Cette affirmation figure dans [le rapport initial](../results/v1_prototype/rapport_incident.md), lignes 24–30 et 141. Cette IP n'apparaît pourtant ni dans les événements EDR ni dans le script. Le motif `UNION SELECT` est également présenté comme observé alors qu'il est absent des journaux fournis. La chronologie attribue à l'attaquant les accès de 18 h 12 et 18 h 45, qui proviennent d'adresses internes.

`V2 — Agent outillé` cesse de présenter le lien comme confirmé, reprend mieux les événements du poste et produit une YARA syntaxiquement utilisable. Il conserve cependant une « possibilité élevée » d'attaque coordonnée et un « même acteur probable », sans nouvel élément probant. Sa chronologie invente encore des chemins `/test`, `/debug` et des téléchargements à 23 h 15, et attribue toujours des accès internes précoces à `203.0.113.42`.

Les citations commencent à apparaître dans `mitre.json` et le confinement, mais `app.log:7-22` dépasse les dix lignes du fichier. Le fichier nommé `mitre.json` est d'ailleurs du texte libre, et non du JSON. Le rapport indique que Sigma est validée alors que la règle finale est rejetée par pySigma. `todos.md` annonce un `iocs.json` absent et quatre actions de confinement, alors que `containment.json` ne contient que deux actions. Ce dernier les déclare approuvées, pendant que le rapport les présente encore en attente. Faute de journal d'approbation séparé dans ce dossier, la provenance de ces statuts ne peut pas être confirmée à partir des sorties seules ; cela ne suffit pas à les déclarer inventés.

La YARA de cette version détecte effectivement le script et ne déclenche sur aucun des six échantillons bénins fournis lors de la revalidation. Mais sa condition `any of (...)` accepte aussi une simple mention de `192.168.1.100`, comme le confirme le contre-exemple ajouté. Le gain porte donc sur l'exécutabilité de la règle, sans démontrer sa spécificité.

**De `V2 — Agent outillé` à `V3 — Harness structuré` : principal progrès de contrôle et d'honnêteté du résultat**

`V3 — Harness structuré` abandonne l'attribution d'un acteur commun, normalise la chronologie en UTC, introduit des constats identifiés et distingue `observe`, `tentative_bloquee` et `present_dans_script`. Le mapping contient des identifiants et libellés officiels. L'instruction malveillante du User-Agent à `web_access.log:7` est signalée explicitement.

Le changement le plus utile est que les livrables invalides ne sont plus présentés comme un parcours réussi. [validation_finale.json](../results/v3_harness_structure/validation_finale.json) déclare l'échec des IOC et de YARA, puis le blocage du confinement. Le rapport final reste incomplet. Pour un harness de sécurité, cette déclaration fidèle d'un échec est une amélioration réelle, même si le nombre de livrables exploitables baisse par rapport à ce qu'annonçait la version précédente.

L'audit montre cependant une difficulté de récupération : après correction de la majorité des références IOC, il manque encore les deux occurrences du nom du script dans le ticket et une occurrence de `admin` dans le ticket. Le modèle répète son lot sans résoudre ces omissions et atteint la limite de trois appels invalides. Le refus protège la provenance, mais le retour générique ne l'aide pas suffisamment à corriger le problème. Ces valeurs ne sont pas pour autant inventées : c'est leur enregistrement conforme qui échoue.

La compréhension reste imparfaite. Le résumé parle de « vol de credentials » comme d'un fait acquis. Le scan de répertoires est associé à T1046, dont la recherche de services réseau correspond moins directement à ce qui est montré que la reconnaissance externe retenue ensuite. Le bypass AMSI est rattaché à T1027 avec une justification qui décrit le contournement de défense, plutôt que l'obfuscation elle-même. La YARA finit par ne plus compiler ; ses premières versions échouaient déjà à détecter le script.

**De `V3 — Harness structuré` à `V4 — Validation des détections` : détections réparées, compréhension partiellement améliorée**

Les choix T1190 pour l'exploitation SQLi de l'application exposée et T1685 pour la tentative de neutralisation d'AMSI sont plus cohérents. T1685 est bien un identifiant officiel actuel ; il ne faut pas le rejeter parce qu'une ancienne connaissance du référentiel attendrait T1562.001. Le snapshot local marque ce dernier révoqué, et la [fiche officielle T1685](https://attack.mitre.org/techniques/T1685/) confirme la technique.

YARA compile et détecte enfin l'échantillon après deux essais ; Sigma passe dès le premier essai. C'est un progrès concret par rapport à `V3 — Harness structuré`. Toutefois, la branche YARA qui déclenche est `CurrentVersion\Run` ET `New-ScheduledTaskAction` : les chaînes littérales `amsiInitFailed` et `AmsiUtils` ne sont pas présentes sous cette forme, car le script les construit par concaténation. La règle réussit donc son test sans reconnaître le bypass AMSI annoncé dans son nom. Un petit exemple bénin contenant une clé Run et la préparation d'une tâche de sauvegarde déclenche également la règle.

Un progrès analytique discret est le décodage de `facture_2024-11.ps1.txt:12`, consigné dans [derivations.json](../results/v4_validation_detection/derivations.json). Le texte décodé contient exactement `http://192.168.1.100/stage.ps`. Ce n'est pas l'URL en clair `http://192.168.1.100/stage1.ps1` de la ligne 22. L'écart est réel et mérite d'être conservé ; corriger automatiquement l'une vers l'autre créerait une information fausse. Mais ce résultat n'est pas exploité dans les IOC finaux ni dans le rapport, puisque l'étape IOC échoue encore.

L'audit confirme que le dernier lot IOC omet toujours `facture_2024-11.ps1.txt:144` pour `192.168.1.100`, ainsi que plusieurs occurrences de `admin`. Le confinement demeure bloqué. Le mapping gagne le keylogging, mais perd T1053.005 pour la tâche planifiée. L'amélioration n'est donc pas uniforme.

**De `V4 — Validation des détections` à `V5 — Validation humaine` : parcours complet, mais plusieurs régressions de fond**

La dernière sortie enregistre enfin les IOC, propose trois actions, recueille une acceptation humaine distincte et produit un protocole manuel lié à la proposition par empreinte. Les constats sont mieux séparés : SQLi tentée puis extraction, AMSI, persistance et keylogging. T1053.005 revient dans le mapping. Ces changements rendent le résultat plus facile à relire et le parcours réellement vérifiable.

En revanche, l'extraction réussit avec un ensemble réduit : `203.0.113.42`, `192.168.1.100`, `admin` et le nom du script. Le domaine observé en DNS, le hash exact du fichier, la seconde IP et toutes les URL sont absents. Le décodage Base64 présent dans `V4 — Validation des détections` n'est plus réalisé. La validité des indicateurs conservés progresse, tandis que la couverture de l'enquête recule.

Cette couverture doit être évaluée selon la valeur analytique des informations omises :

| Indicateur à conserver ou examiner | Source exacte | Rôle et niveau de preuve |
|---|---|---|
| `203.0.113.42` | `web_access.log:19`, `:43`, `:50-51` ; `app.log:7` | Source observée des requêtes et de la connexion administrative |
| `192.168.1.100` | `edr_events.jsonl:6` ; script `:22`, `:144` | Destination d'une connexion bloquée et adresses déclarées dans le code |
| `malicious-domain.ru` | `edr_events.jsonl:5` ; script `:24` | Résolution DNS observée en échec ; URL déclarée dans le code |
| `192.168.1.101` | script `:23` | Adresse déclarée seulement, aucune connexion fournie |
| `064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40` | `edr_events.jsonl:1` | Hash EDR, égal au SHA-256 de la copie du script |
| `http://192.168.1.100/stage1.ps1` | script `:22` | URL déclarée ; téléchargement non démontré |
| `http://192.168.1.101/beacon.exe` | script `:23` | URL déclarée ; téléchargement non démontré |
| `http://malicious-domain.ru/payload.dll` | script `:24` | URL déclarée ; téléchargement non démontré |
| `http://192.168.1.100:8080/beacon` | script `:144` | Envoi commenté ; l'EDR ne fournit que la destination IP/port bloquée |
| `http://192.168.1.100/stage.ps` | script `:12`, Base64/UTF-16LE | Valeur dérivée, provenance à conserver ; exécution non démontrée |

Les entités `PC-COMPTA-07`, `CORP\m.durand` et `admin` sont également utiles à l'enquête et au confinement. Leur présence ne prouve pas à elle seule qu'un compte a été volé ou qu'une machine héberge un C2. Le type et le rôle de chaque entité doivent rester explicites.

La YARA finale régresse fortement en spécificité : `any of them` accepte une seule occurrence de `ToUnicode`, `GetAsyncKeyState`, `sandboxIndicators`, `amsiInitFailed` ou de l'URL. La revalidation confirme qu'elle déclenche séparément sur `Write-Host "ToUnicode"`, un commentaire documentaire sur `GetAsyncKeyState`, une variable `sandboxIndicators` et une note contenant `amsiInitFailed`. Ce sont des contre-exemples concrets à l'idée que le résultat « zéro faux positif sur six scripts » suffirait à valider la règle pour le SOC.

**Sigma : amélioration de syntaxe, sémantique encore mal maîtrisée**

| Sortie | Résultat indépendant sur la règle finale |
|---|---|
| `V1 — Prototype` | pySigma : identifiant non UUID ; la structure contient aussi des clés `OR RequestURI` incorrectes |
| `V2 — Agent outillé` | pySigma : absence de condition dans `detection` ; `condition` est placé à la racine |
| `V3 — Harness structuré` | Détecte le positif et aucun des quatre négatifs, mais `CommandLine\|contains` est écrit deux fois ; le parseur conserve la dernière valeur, `WindowStyle Hidden` |
| `V4 — Validation des détections` | Détecte le positif et aucun des quatre négatifs ; la liste des deux options impose Bypass OU Hidden |
| `V5 — Validation humaine` | Même comportement que `V4 — Validation des détections` |

Dans les trois dernières versions, le parent Outlook et l'image PowerShell sont bien exigés. Mais aucune n'impose réellement les deux options comme le suggèrent leurs descriptions. Le test ajouté avec Outlook → PowerShell + Hidden seul déclenche dans les trois cas. Avec Bypass seul, il déclenche dans `V4 — Validation des détections` et `V5 — Validation humaine`, mais pas dans `V3 — Harness structuré`. La [documentation Sigma sur `all`](https://sigmahq.io/docs/basics/modifiers.html#all) confirme qu'une liste est un OU par défaut ; `contains|all` permettrait d'exiger les deux valeurs si telle est l'intention. Une détection volontairement plus large peut être pertinente, à condition de l'assumer dans la description et dans les tests.

Le corpus n'a aucun cas Outlook → PowerShell avec une seule option : il ne peut donc pas détecter cet écart d'intention. Les trois réussites Sigma ne prouvent pas que la règle correspond à sa description. Il faut également refuser les clés YAML dupliquées avant la conversion par un parseur permissif.

**ATT&CK : l'existence d'une technique ne valide pas son association**

Les deux premières sorties contiennent des erreurs objectives de libellés. Par exemple, T1088 n'est pas une technique d'exfiltration HTTP ; T1571 n'est pas du staging ; T1059.005 désigne Visual Basic, et non « Command Shell » ; T1071.004 désigne DNS. Les dernières sorties éliminent ces erreurs en reprenant les entrées officielles, ce qui est un progrès substantiel.

Le contrôle sémantique reste insuffisant :

- T1020 est associé systématiquement aux exports web. Or le volume, le format CSV/SQL et le code HTTP ne démontrent pas une automatisation. La [définition officielle de T1020](https://attack.mitre.org/techniques/T1020/) exige précisément un traitement automatisé. Il faut distinguer le constat d'export de l'hypothèse sur son mode opératoire.
- T1110 est plausible au regard des cinq réponses 401 puis du succès, mais les citations attachées ne montrent que le succès (`web_access.log:43`, `app.log:7`). Il manque `web_access.log:38-42`, et la méthode exacte d'obtention des identifiants doit rester incertaine.
- Le dernier mapping remplace T1547.001 par T1112 pour les clés Run/RunOnce. T1112 n'est pas faux comme description générale d'une modification de registre, mais il perd la précision du mécanisme de persistance visible dans le code.
- Les dernières analyses négligent des comportements directement journalisés : recherche d'antivirus (`edr_events.jsonl:3`), interrogation BIOS (`:4`) et DNS (`:5`). La recherche d'antivirus est notamment un meilleur candidat sourcé à T1518.001 que plusieurs capacités seulement déclarées. Une requête BIOS seule ne prouve toutefois pas tout un mécanisme anti-sandbox réussi.

Les références sont aussi parfois trop larges ou incomplètes pour les affirmations. Dans `V5 — Validation humaine`, C1 mentionne `.env` sans citer sa ligne 13 ; C2 mentionne `/api/users/` mais cite seulement `/search` et une erreur applicative ; C5 mentionne les backups mais ne cite pas leur téléchargement aux lignes 50–51. L'information existe dans le dossier, mais les références attachées ne prouvent pas tout le constat. Dans `V3 — Harness structuré` et `V4 — Validation des détections`, le constat combinant AMSI, registre, tâche et keylogging est réutilisé pour plusieurs techniques alors que ses références ne citent pas l'enregistrement de la tâche.

La chronologie finale omet par ailleurs les téléchargements de 01:00 UTC, les requêtes WMI, le DNS et l'isolement de 08:42:15 UTC. Ce sont des pertes de compréhension opérationnelle, pas un problème de longueur du rapport.

**Confinement final : approbation bien tracée, contenu à corriger avant application**

La séparation entre [proposition](../results/v5_validation_humaine/proposition_confinement.json), [décision](../results/v5_validation_humaine/containment.json) et [protocole](../results/v5_validation_humaine/protocole_confinement.md) est le principal progrès final. La décision est inscrite par l'hôte dans l'audit, avec l'empreinte de la proposition. Les sorties ne prétendent pas exécuter les actions. Les deux premières recommandations, blocage de la source web et sécurisation du compte applicatif `admin`, sont cohérentes avec les faits, sous réserve du périmètre opérationnel.

Trois défauts de fond subsistent :

1. L'action A3 est une isolation de `PC-COMPTA-07`, mais sa cible structurée est `facture_2024-11.ps1`. Le protocole reprend exactement cette mauvaise cible, tout en donnant des instructions sur le poste. Le contrôle d'identité de la cible approuvée fonctionne donc sans garantir que son type correspond à l'action.
2. Le poste est déjà isolé selon `edr_events.jsonl:7` et le ticket. Il faudrait proposer de vérifier et maintenir cette isolation, plutôt que traiter son activation comme une action nouvelle. Le constat d'isolement manque à l'analyse finale.
3. L'impact attendu affirme que l'isolation arrêtera le script et la persistance. Couper le réseau ne supprime ni un processus local ni une persistance locale. Le retour arrière A2 prévoit aussi de restaurer l'ancien mot de passe d'un compte considéré compromis : cette consigne ne devrait pas être retenue.

Le protocole ne traite pas explicitement les sessions web déjà ouvertes, le périmètre exact du compte applicatif et la conservation des preuves. Ces manques n'annulent pas l'intérêt d'un accord humain ; ils montrent que l'accord doit porter sur une proposition techniquement cohérente. L'empreinte sécurise le lien avec le document approuvé, pas la pertinence de son contenu.

**Ce qu'il faudrait mesurer ou renforcer ensuite dans le harness**

1. **Vérifier le sens des constats.** Exiger des constats atomiques, chacun avec les lignes qui soutiennent toute l'affirmation ; séparer fait observé, interprétation et hypothèse causale. Tester explicitement les pièges de ce corpus : acteur commun inventé, mot de passe supposé volé, tâche commentée présentée comme installée, connexion bloquée présentée comme exfiltration réussie.
2. **Mesurer la couverture des IOC importants.** Un run ne doit pas paraître meilleur simplement parce qu'il réduit sa liste aux valeurs les plus faciles à enregistrer. Évaluer séparément les valeurs observées en télémétrie, celles présentes seulement dans le code et celles dérivées. Conserver les transformations et distinguer `stage.ps` de `stage1.ps1`.
3. **Confier les occurrences au code.** Le modèle choisit une valeur, son contexte et ses constats ; le harness peut conserver les références immuables renvoyées par la vérification, au lieu de demander au modèle de recopier des dizaines de références. Les citations qui démontrent le rôle malveillant doivent rester distinctes des simples occurrences textuelles. Par exemple, `admin` dans une URL, dans le ticket et dans une identité authentifiée n'a pas la même signification.
4. **Tester les conditions des règles.** Refuser les doublons YAML ; vérifier les cas avec zéro, une ou deux options PowerShell. Pour YARA, introduire des scripts proches et des extraits documentaires, contrôler quelles chaînes ont réellement déclenché et demander une combinaison d'indices suffisamment spécifique. Conserver aussi des positifs de validation non utilisés pendant les corrections, pour éviter l'ajustement au seul échantillon.
5. **Contrôler action, cible et état existant.** Représenter le type d'action et le type de cible : isolation → hôte, blocage → IP/domaine, désactivation → compte dans un système identifié. Rejeter A3 tant que la cible est un fichier. Tenir compte du confinement déjà effectué et soumettre les impacts et retours arrière à une vérification de cohérence.
6. **Séparer les verdicts.** Présenter distinctement complétude du parcours, intégrité/provenance, réussite des tests locaux, couverture de l'enquête et validation humaine du fond. Garder le modèle et les snapshots fixes pour les comparaisons et répéter les runs ; les cinq sorties présentes montrent des cas d'amélioration, pas un taux de fiabilité général.

**Appréciation finale : `V1 — Prototype` est un brouillon très halluciné ; `V2 — Agent outillé` apporte des outils sans maîtriser les résultats ; `V3 — Harness structuré` introduit le gain majeur de contrôle et de transparence ; `V4 — Validation des détections` répare les détections sans débloquer les IOC ; `V5 — Validation humaine` complète le parcours, avec une provenance plus solide mais des défauts sémantiques encore importants. Le prochain progrès décisif consiste à empêcher qu'une conclusion ou une action incorrecte soit acceptée uniquement parce que ses références existent et que son schéma est valide.**
