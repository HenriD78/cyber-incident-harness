# Guide d’utilisation

Les commandes ci-dessous se lancent depuis la racine du dépôt, après installation en mode éditable.
Le code du harness se trouve dans `src/cyber_harness/` ; le cas étudié dans `examples/inc_2026_0417/`.
Les nouvelles sorties utilisent `artifacts/latest/`, séparément des résultats historiques de `results/`.

Aucun script de l’incident ni aucune action de confinement n’est exécuté. Après acceptation humaine,
le harness rédige un protocole manuel ; après refus, il clôture le rapport sans protocole.

## Installation et lancement

Python **3.11 ou supérieur**. Les versions des dépendances testées sont fixées dans
`requirements.txt` (dont DeepAgents 0.7.32).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m scripts.telecharger_mitre
python -m cyber_harness --run-label evaluation
```

Le modèle par défaut est `gemma4:31b-cloud`. Ollama et l'accès au modèle doivent être
configurés. `TD3_MODEL` permet de le remplacer :

```bash
TD3_MODEL=gemma4:31b-cloud TD3_RUN_LIMIT=200 python -m cyber_harness
```

Au démarrage, l'hôte compare la version locale avec l'index officiel MITRE, télécharge
une nouvelle version si nécessaire et conserve un snapshot en mémoire pendant le run.
Le téléchargement ne passe pas par le modèle. Une panne réseau conserve la copie locale
mais indique `fraicheur: non_verifiee` ; la clôture ne revendique alors pas une réussite
complète. Une version révoquée/obsolète ne peut pas être enregistrée dans le mapping.

Les sorties de travail précédentes sont archivées dans `artifacts/runs/` avec date UTC et identifiant unique.
Le modèle effectif et le `thread_id` sont affichés. Les codes de sortie sont :

- `0` : parcours complet, y compris un refus humain suivi du rapport ;
- `1` : analyse incomplète ou contrôle en échec ;
- `2` : configuration ou arguments de lancement invalides ;
- `130` : interruption humaine ou fermeture de l'entrée console.

## Parcours contrôlé

| Phase | Outils métier et résultat |
|---|---|
| Preuves | `list_evidence`, `read_evidence`, `to_utc`, `save_analysis` → analyse et chronologie |
| IOC | `verify_ioc`, `decode_evidence`, `save_iocs` → valeurs et provenance |
| ATT&CK | `search_mitre`, `check_mitre`, `save_mitre` → descriptions officielles et constats associés |
| Détection | `validate_sigma`, `test_yara` → règles et résultats exacts, quatre essais maximum par moteur |
| Confinement | `propose_containment` → une proposition consolidée, puis décision recueillie par l'hôte |
| Protocole | `save_protocol`, uniquement après accord → consignes manuelles pour les actions/cibles approuvées |
| Rapport | `save_report_summary` → synthèse sourcée, rapport assemblé et validé par l'hôte |

Les six procédures `skills/*/SKILL.md` sont accessibles en lecture seule. Le système de
fichiers générique de l'agent est limité à ce répertoire. Les preuves sont accessibles
uniquement par les outils de lecture ; `read_artifact` relit les résultats de la session.
Le modèle n'a pas d'outil shell, de navigation réseau, de délégation, d'approbation ou
écriture arbitraire. Les outils refusent les opérations hors de leur phase.

Une référence est un objet `{fichier, ligne, sha256}`, avec ligne à partir de **1**.
Le harness vérifie les bornes, l'empreinte, la couverture de lecture, les identifiants
de constats et les associations entre livrables. Les statuts sont `observe`,
`tentative_bloquee`, `present_dans_script`, `hypothese`. Une date source est convertie
en UTC par l'outil et contrôlée à l'enregistrement. Une proximité temporelle seule
ne prouve pas un lien causal.

La vérification d'un IOC conserve toutes les occurrences de la valeur complète :
`203.0.113.4` ne correspond pas à `203.0.113.42`. Un IOC décodé garde la ligne encodée,
son empreinte et la transformation dans `derivations.json`. La présence textuelle
ne prouve pas le caractère malveillant ; le modèle doit préciser le contexte.

`read_evidence` accepte `debut` à partir de 1 ou `offset` à partir de 0, jamais les
deux : `debut=101` et `offset=100` lisent la même ligne. Les paramètres inconnus sont
refusés par les outils métier. Chaque page indique les nouvelles lignes consultées,
la couverture du fichier et `lecture_suivante` pour combler les portions non lues.
Atteindre la fin du fichier ne suffit pas si une page précédente a été sautée.

## Récupération et dépendances entre phases

Un appel métier refusé renvoie une erreur structurée : champs à corriger, gabarit
complet des arguments lorsque disponible, fichiers accessibles et identifiants de
constats réellement enregistrés. Le harness ne complète pas automatiquement les
preuves, empreintes ou identifiants manquants. Les erreurs sont regroupées pour
éviter qu'une longue liste d'erreurs de schéma masque la correction attendue.
Pour les IOC, toutes les erreurs du lot sont vérifiées avant écriture : le retour
indique la valeur, le champ, les références exactes manquantes ou inattendues, et
l'appel de vérification requis s'il manque. Une correction peut ainsi résoudre
plusieurs IOC en une tentative. Le harness n'accepte pas un lot partiellement valide.
La proposition de confinement reçoit également les erreurs de toutes ses actions
en une fois, avec les références autorisées par constat et les cibles IOC vérifiées.
`cible` contient la valeur exacte (`admin`, non `compte admin`) ; le type et le
système concerné figurent dans `action` ou `justification`. Le harness ne réécrit
pas une cible approximative et n'infère jamais un accord humain d'une correction.

Trois appels invalides au même outil dans une phase arrêtent cette phase, même si
les arguments changent. Si le modèle termine sans livrable valide, l'hôte autorise
au plus deux relances, avec l'historique des lectures, erreurs et appels conservé.
Le budget LLM global n'est jamais remis à zéro par ces corrections. Les quatre
essais maximum par moteur Sigma/YARA continuent à s'appliquer.

Une réponse sans texte ni appel d'outil est diagnostiquée avant toute progression.
Le journal `diagnostic_reponse_modele` compare les tailles et appels reçus du client
Ollama avec le message converti, sans conserver le contenu du raisonnement. La première
récupération désactive le streaming et le raisonnement. Après deux réponses vides,
la tentative suivante demande un JSON texte sans outils natifs. Seuls les outils
d'enregistrement de la phase sont admis dans l'enveloppe `{tool, arguments}` ; le
JSON passe ensuite par les mêmes outils typés et validations métier. Une référence
inexistante reste refusée. Les conversions et refus figurent dans `transport_json`.
Cette récupération utilise les relances et le budget existants ; elle ne garantit
pas qu'un modèle produise une analyse correcte ou complète.

L'hôte vérifie l'état métier, la présence et les empreintes des livrables avant de
valider une phase. Les prérequis sont :

| Phase | Prérequis vérifiés |
|---|---|
| IOC | Analyse des preuves enregistrée et lecture complète |
| MITRE | Analyse des preuves enregistrée |
| Règles | Analyse et mapping MITRE enregistrés |
| Confinement | Analyse et IOC enregistrés |
| Protocole | Proposition enregistrée et acceptation humaine |
| Synthèse du rapport | Analyse enregistrée avec identifiants de constats valides |

Un échec d'extraction des IOC laisse possible le mapping des comportements et les
tests de détection, mais bloque la proposition de confinement. Un échec YARA reste
signalé dans le rapport et n'interdit pas un confinement justifié par des constats
et IOC vérifiés. Une analyse absente bloque toutes ces phases dépendantes : l'hôte
assemble alors directement un rapport de secours, sans demander au modèle de
produire une synthèse avec des identifiants inexistants.

`etat_phases.json`, également repris dans les diagnostics, indique les phases
terminées, en échec, bloquées, ignorées ou clôturées en secours, avec les raisons et
le nombre d'invocations. Le journal conserve les erreurs récupérées et les relances ;
une erreur corrigée ne suffit pas, à elle seule, à invalider tout le run.

## Tests des règles

`detection_corpus.json` décrit explicitement les échantillons YARA et les événements
Sigma positifs/négatifs. Pour ce TD, le positif Sigma attendu est `edr_events.jsonl:2` ;
les négatifs incluent des lancements PowerShell administratifs et des événements proches.

L'évaluateur Sigma local prend en charge `windows/process_creation` sans `service`,
les champs mappés dans `src/cyber_harness/detection/sigma.py`, AND/OR/NOT, chaînes et jokers, mots-clés, nombres,
booléens et null. Les autres expressions/sources sont **non concluantes**, jamais
validées par défaut. Ce sous-ensemble ne remplace pas un backend SIEM complet.

YARA compile et analyse les octets dans un processus séparé : inclusions externes
interdites, timeout global de huit secondes, deux secondes par match et limite CPU
sur les plateformes POSIX compatibles. Aucun échantillon n'est lancé. Un corpus bénin
vide/manquant ne peut pas donner un verdict positif. Le processus est borné mais ne
constitue pas une machine virtuelle ; il suppose les bibliothèques installées fiables.

Chaque essai conserve les empreintes de la règle et du corpus. La validation finale
refuse une règle ou un corpus modifié depuis son test. Réussir ces tests locaux ne
certifie pas l'absence de faux positifs dans un autre environnement.

## Sorties et trace des décisions

Principaux fichiers de `artifacts/latest/` :

- `manifest_preuves.json`, `analyse.json`, `chronologie.md`, `iocs.json`, `mitre.json` ;
- `referentiel.json`, `derivations.json` lorsqu'un décodage est utilisé ;
- `regle_sigma.yml`, `regle_yara.yar`, `tests/`, `resultats_tests.json` ;
- `proposition_confinement.json`, `containment.json` (décision humaine et empreinte de la proposition) ;
- `protocole_confinement.json` et `.md`, seulement après acceptation ;
- `rapport_incident.md`, `validation_finale.json`, `diagnostic_execution.json`, `etat_phases.json` ;
- `audit.jsonl`, journal local des phases, appels, résultats, erreurs, livrables et décisions.

Le journal contient les identifiants parent/enfant des appels et une chaîne SHA-256.
Il permet de suivre : preuve → constat → IOC/technique → règle/test → proposition →
décision → protocole. Les décisions et résultats sont écrits par le harness, jamais
par une écriture générique du modèle. Les secrets d'environnement identifiés sont
masqués ; les preuves, prompts et réponses peuvent néanmoins contenir des données
sensibles. La chaîne détecte une altération dans la session ; ce n'est pas un registre
signé résistant à un administrateur qui contrôlerait l'hôte.

Le budget global par défaut est de 200 appels LLM, dont dix réservés au rapport
(adapté aux petits budgets). `TD3_REPEAT_LIMIT=4` bloque le quatrième appel consécutif
identique, **écritures incluses**. Les lectures identiques d'un même lot sont dédupliquées.
Les appels ne sont pas remis à zéro entre les phases et après la décision humaine.
Le diagnostic conserve la première raison d'arrêt, même après l'ouverture du
budget réservé au rapport de secours.
Une clôture de secours assemble un rapport partiel depuis les résultats disponibles.
Les contrôles de références et d'intégrité ne certifient pas l'interprétation du modèle :
l'analyste doit relire les conclusions et le protocole avant de l'appliquer.

## LangSmith facultatif

La trace locale fonctionne sans clé LangSmith. Pour activer en plus la trace distante :

```bash
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY=...            # jamais dans les sources
export LANGSMITH_PROJECT=td3-dargent-genot
# Pour un compte hébergé en Europe :
export LANGSMITH_ENDPOINT=https://eu.api.smith.langchain.com
python -m cyber_harness
```

Une clé valide et un éventuel `LANGSMITH_WORKSPACE_ID` réel sont nécessaires.
Le modèle cloud et LangSmith, s'ils sont utilisés, reçoivent les données transmises
à leurs services. La trace locale ne garantit pas le masquage de leurs propres traces.

`scripts/exporter_trace.py` reste disponible pour lire des traces existantes :

```bash
python -m scripts.exporter_trace --list
python -m scripts.exporter_trace --thread-id THREAD_AFFICHE
python -m scripts.exporter_trace --run-id UUID
```

L'export ne lance ni le modèle ni l'agent. Il exige une clé autorisée en lecture.
`--thread-id` rassemble les différentes phases du même run ; attendre leur ingestion.
Le JSON conserve les spans, liens parent/enfant, entrées/sorties, erreurs, durées et
compteurs de tokens disponibles. Les pièces jointes ne sont pas téléchargées.
Options : `--project`, `--output`, `--limit` pour la liste. Les fichiers existants
ne sont pas écrasés. Des spans absents/masqués côté service ne sont pas reconstruits.

## Vérification hors réseau

```bash
python -m unittest discover -s tests -t . -v
```

Les tests utilisent des faux modèles et des répertoires temporaires. Ils couvrent
les outils, les budgets, les références, la mise à jour MITRE avec réponses simulées,
les contournements d'accès, les faux positifs, les inclusions YARA, les timeouts,
l'intégrité des livrables, les parcours acceptation/refus et la récupération d'un
appel save_analysis mal formé reproduit depuis le journal d'un run réel. Ils vérifient
aussi les réponses fournisseur vides, la récupération JSON texte, les références
invalides et les outils interdits dans ce transport. Les preuves et sorties
existantes ne sont pas modifiées. Aucun modèle Ollama n'est appelé.

Le prototype est conservé dans `examples/agent_baseline.py` ; il ne bénéficie pas
des garanties du harness. `--run-label` (`--version` en alias) reste une étiquette
d’exécution, indépendante des versions V1 à V5 de l’évaluation. Les anciens livrables archivés restent lisibles mais ne sont pas migrés
vers les nouveaux contrats typés et ne peuvent pas être repris comme état d'un run.
