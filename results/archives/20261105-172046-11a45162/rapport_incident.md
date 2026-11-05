# Rapport d'incident INC-2026-0417

**Statut : INCOMPLET / NON VALIDÉ**

## Résumé exécutif

L'incident combine deux campagnes distinctes sans lien technique prouvé. Une première attaque web a mené à une compromission du serveur via injection SQL et brute force, aboutissant à l'exfiltration massive de données clients. Parallèlement, un poste de travail (PC-COMPTA-07) a été infecté par un malware PowerShell via phishing, présentant des capacités d'espionnage et de persistance, bien que les communications C2 aient été bloquées.
Sources : web_access.log:8, web_access.log:12, web_access.log:23, app.log:3, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, app.log:8, web_access.log:50, app.log:9, edr_events.jsonl:2, edr_events.jsonl:3, edr_events.jsonl:4, edr_events.jsonl:5, edr_events.jsonl:6, facture_2024-11.ps1.txt:17, facture_2024-11.ps1.txt:54, facture_2024-11.ps1.txt:72, facture_2024-11.ps1.txt:117

## Qualification et lien entre alertes

- alerte_web : Compromission confirmée du serveur web via injection SQL et brute force, menant à l'exfiltration massive de données clients. (web_access.log:8, web_access.log:12, web_access.log:23, app.log:3, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, app.log:8, web_access.log:50, app.log:9).
- alerte_poste : Infection par malware via phishing (PowerShell), avec tentatives de C2 et capacités de persistance/espionnage, stoppée par l'isolation du poste. (edr_events.jsonl:2, edr_events.jsonl:3, edr_events.jsonl:4, edr_events.jsonl:5, edr_events.jsonl:6, facture_2024-11.ps1.txt:17, facture_2024-11.ps1.txt:54, facture_2024-11.ps1.txt:72, facture_2024-11.ps1.txt:117).

Aucun lien prouvé : Aucun lien technique direct (IP, compte, fichier) n'est prouvé entre l'attaque web (203.0.113.42) et l'infection du poste (192.168.1.100). Les deux semblent être des campagnes distinctes ou des phases d'une attaque plus large non encore corrélée.
Sources du lien : non vérifié

## Chronologie et constats

- C1 — 2024-11-15T21:15:01Z — observe : Scan de répertoires administratifs et fichiers sensibles depuis l'IP 203.0.113.42 (web_access.log:8, web_access.log:12).
- C2 — 2024-11-15T21:18:30Z — observe : Tentatives d'injection SQL réussies sur le paramètre 'q' de /search, permettant l'énumération de la table 'users' (web_access.log:23, app.log:3).
- C3 — 2024-11-15T21:22:15Z — observe : Extraction de données sensibles (table users) via injection SQL (web_access.log:25, app.log:4).
- C4 — 2024-11-15T22:20:06Z — observe : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses (Brute force/Credential Stuffing) (web_access.log:43, app.log:7).
- C5 — 2024-11-15T22:21:45Z — observe : Exfiltration de données massives via l'interface admin (exports SQL et CSV) (web_access.log:47, app.log:8).
- C6 — 2024-11-16T01:00:11Z — observe : Téléchargement de dumps de base de données et fichiers clients (web_access.log:50, app.log:9).
- C7 — 2024-11-16T08:42:10Z — observe : Exécution d'un script PowerShell malveillant via Outlook sur PC-COMPTA-07 (edr_events.jsonl:2).
- C8 — 2024-11-16T08:42:11Z — observe : Collecte d'informations système (Antivirus, BIOS) via WMI (edr_events.jsonl:3, edr_events.jsonl:4).
- C9 — 2024-11-16T08:42:12Z — tentative_bloquee : Tentative de résolution DNS vers un domaine malveillant (malicious-domain.ru) - NXDOMAIN (edr_events.jsonl:5).
- C10 — 2024-11-16T08:42:13Z — tentative_bloquee : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy (edr_events.jsonl:6).
- C11 — date non vérifiée — present_dans_script : Capacité de contournement AMSI présente dans le script (facture_2024-11.ps1.txt:17).
- C12 — date non vérifiée — present_dans_script : Capacité de persistance via Tâches Planifiées et Registre présente dans le script (facture_2024-11.ps1.txt:54, facture_2024-11.ps1.txt:72).
- C13 — date non vérifiée — present_dans_script : Capacité de keylogging via API user32.dll présente dans le script (facture_2024-11.ps1.txt:117).

## IOC vérifiés

- ip `203.0.113.42` : Adresse IP source des scans de répertoires administratifs et des injections SQL. ; confiance haute ; app.log:7, web_access.log:7, web_access.log:8, web_access.log:9, web_access.log:10, web_access.log:11, web_access.log:12, web_access.log:13, web_access.log:14, web_access.log:15, web_access.log:16, web_access.log:17, web_access.log:18, web_access.log:19, web_access.log:20, web_access.log:21, web_access.log:22, web_access.log:23, web_access.log:24, web_access.log:25, web_access.log:26, web_access.log:30, web_access.log:31, web_access.log:32, web_access.log:33, web_access.log:34, web_access.log:35, web_access.log:36, web_access.log:37, web_access.log:38, web_access.log:39, web_access.log:40, web_access.log:41, web_access.log:42, web_access.log:43, web_access.log:44, web_access.log:45, web_access.log:46, web_access.log:47, web_access.log:50, web_access.log:51 ; constats C1
- domaine `malicious-domain.ru` : Domaine malveillant contacté par le script PowerShell. ; confiance haute ; edr_events.jsonl:5, facture_2024-11.ps1.txt:24 ; constats C9
- ip `192.168.1.100` : Adresse IP interne cible d'une tentative de connexion bloquée par le proxy. ; confiance haute ; edr_events.jsonl:6, facture_2024-11.ps1.txt:22, facture_2024-11.ps1.txt:144 ; constats C10
- compte `admin` : Compte administrateur compromis après brute force. ; confiance haute ; app.log:5, app.log:7, ticket_INC-2026-0417.md:7, web_access.log:8, web_access.log:20, web_access.log:26, web_access.log:44, web_access.log:45, web_access.log:46, web_access.log:47, web_access.log:50, web_access.log:51, web_access.log:55, web_access.log:56, web_access.log:57 ; constats C4
- autre `PC-COMPTA-07` : Poste de travail infecté par le script PowerShell malveillant. ; confiance haute ; edr_events.jsonl:1, edr_events.jsonl:2, edr_events.jsonl:3, edr_events.jsonl:4, edr_events.jsonl:5, edr_events.jsonl:6, edr_events.jsonl:7, ticket_INC-2026-0417.md:10 ; constats C7

## MITRE ATT&CK

{"derniere_version":"20.1","fraicheur":"a_jour","sha256":"539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5","source":"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json","verifie_le":"2026-11-05T17:04:41.640053+00:00","version":"20.1"}
- T1595 — Active Scanning (reconnaissance) : Scan de répertoires administratifs et fichiers sensibles pour identifier des cibles et des données d'intérêt.
  - C1 : observe ; web_access.log:8, web_access.log:12
- T1213.006 — Databases (collection) : Utilisation d'injections SQL pour énumérer et extraire des données sensibles depuis la base de données 'users'.
  - C2 : observe ; web_access.log:23, app.log:3
  - C3 : observe ; web_access.log:25, app.log:4
- T1110 — Brute Force (credential-access) : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses, caractéristique d'un brute force ou credential stuffing.
  - C4 : observe ; web_access.log:43, app.log:7
- T1020 — Automated Exfiltration (exfiltration) : Exfiltration de données massives (exports SQL, CSV, dumps de base de données) via l'interface d'administration.
  - C5 : observe ; web_access.log:47, app.log:8
  - C6 : observe ; web_access.log:50, app.log:9
- T1059.001 — PowerShell (execution) : Exécution d'un script PowerShell malveillant délivré via un email Outlook.
  - C7 : observe ; edr_events.jsonl:2
- T1082 — System Information Discovery (discovery) : Collecte d'informations système (Antivirus, BIOS) via WMI pour reconnaissance de l'environnement.
  - C8 : observe ; edr_events.jsonl:3, edr_events.jsonl:4
- T1071.004 — DNS (command-and-control) : Tentative de résolution DNS vers un domaine malveillant, typique d'une communication C2 via DNS.
  - C9 : tentative_bloquee ; edr_events.jsonl:5
- T1685 — Disable or Modify Tools (defense-impairment) : Présence d'une capacité de contournement de l'AMSI (Antimalware Scan Interface) pour échapper à la détection.
  - C11 : present_dans_script ; facture_2024-11.ps1.txt:17
- T1053.005 — Scheduled Task (execution, persistence, privilege-escalation) : Capacité de persistance via la création de Tâches Planifiées.
  - C12 : present_dans_script ; facture_2024-11.ps1.txt:54, facture_2024-11.ps1.txt:72
- T1112 — Modify Registry (defense-impairment, persistence) : Capacité de persistance via la modification du Registre.
  - C12 : present_dans_script ; facture_2024-11.ps1.txt:54, facture_2024-11.ps1.txt:72
- T1056.001 — Keylogging (collection, credential-access) : Capacité de keylogging utilisant les API de user32.dll pour capturer les frappes clavier.
  - C13 : present_dans_script ; facture_2024-11.ps1.txt:117

## Règles et résultats exacts

Fichiers : regle_sigma.yml, regle_yara.yar. Résultats locaux, sans certification de déploiement SIEM.
```json
{
  "sigma": {
    "valide": true,
    "test_concluant": true,
    "test_reussi": true,
    "detections_sur_edr": [
      "edr_events.jsonl:2 (process_create)"
    ],
    "regle_sha256": "572a47b1b4b471b02ded074460ddab2e662ea51ad5747e0987225a1f4e62792b",
    "titre": "PowerShell Execution via Outlook",
    "logsource": "SigmaLogSource(category='process_creation', product='windows', service=None, definition=None, source=None, custom_attributes=None)",
    "corpus_sha256": "cb09edd06642a8324f9b4b404c78c26420a60f8f56742c9fc69afb5d46f948e5",
    "faux_positifs": [],
    "faux_negatifs": [],
    "nb_negatifs": 4,
    "tentative": 1
  },
  "yara": {
    "compile": true,
    "test_concluant": true,
    "verdict": "OK",
    "regle_sha256": "c3f57aa04e73b9085c8185ffa04316124d83ba9c8c897287b4f579f27bbe437f",
    "corpus_sha256": "80716d103cb47434d49e2899c9e19578b2907e1f24974b61991dc2c9ef615702",
    "vrais_positifs": [
      "facture_2024-11.ps1.txt"
    ],
    "faux_negatifs": [],
    "faux_positifs": [],
    "nb_scripts_legitimes_testes": 6,
    "tentative": 4
  }
}
```

## Confinement et décision humaine

```json
{
  "proposition": null,
  "decision": null
}
```
Aucune action exécutée par l'agent.

## Tentatives d'injection dans les preuves

web_access.log:7

## Limites et points à confirmer

Les contrôles vérifient les sources et la cohérence des artefacts ; la pertinence des interprétations reste à relire par l'analyste.
- confinement : echec — propose_containment : 3 appels invalides ; dernier refus : Cible non vérifiée dans les preuves/IOC
- Étape incomplète : proposal
- Étape incomplète : decision
- Le script PowerShell a été analysé en version désarmée, certaines fonctionnalités pourraient différer de la version réelle.

## État des phases

```json
{
  "preuves": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 3
  },
  "ioc": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  },
  "mitre": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  },
  "regles": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  },
  "confinement": {
    "statut": "echec",
    "raisons": [
      "propose_containment : 3 appels invalides ; dernier refus : Cible non vérifiée dans les preuves/IOC"
    ],
    "invocations": 1
  },
  "protocole": {
    "statut": "ignoree",
    "raisons": [
      "Aucun accord humain : protocole interdit"
    ],
    "invocations": 0
  },
  "rapport": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  }
}
```

Traçabilité : audit.jsonl, etat_phases.json, manifest_preuves.json, resultats_tests.json et validation_finale.json.
