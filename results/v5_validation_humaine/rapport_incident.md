# Rapport d'incident INC-2026-0417

**Statut : COMPLET — contrôles structurels réussis**

## Résumé exécutif

L'incident combine deux attaques distinctes : une intrusion web réussie via injection SQL (IP 203.0.113.42) menant à l'usurpation du compte admin et l'exfiltration de données clients, et une infection du poste PC-COMPTA-07 par un script PowerShell malveillant via phishing. Le script présente des capacités de bypass AMSI, de persistance et de keylogging, bien que les connexions C2 aient été bloquées. Aucun lien technique n'a été prouvé entre ces deux vecteurs.
Sources : web_access.log:8, web_access.log:12, web_access.log:19, app.log:1, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, app.log:8, edr_events.jsonl:2, edr_events.jsonl:6, facture_2024-11.ps1.txt:18, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:80, facture_2024-11.ps1.txt:117, facture_2024-11.ps1.txt:144

## Qualification et lien entre alertes

- alerte_web : Compromission réussie du serveur web via injection SQL, menant à l'usurpation du compte admin et l'exfiltration de bases de données clients. (web_access.log:8, web_access.log:12, web_access.log:19, app.log:1, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, app.log:8).
- alerte_poste : Infection d'un poste de travail par un script PowerShell malveillant via phishing, avec tentatives de C2 bloquées. (edr_events.jsonl:2, edr_events.jsonl:6, facture_2024-11.ps1.txt:18, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:80, facture_2024-11.ps1.txt:117, facture_2024-11.ps1.txt:144).

Aucun lien prouvé : Aucun lien technique prouvé entre l'attaque web (IP 203.0.113.42) et l'infection du poste (C2 192.168.1.100). Les attaques sont distinctes temporellement et techniquement.
Sources du lien : non vérifié

## Chronologie et constats

- C1 — 2024-11-15T21:15:01Z — observe : Scan de répertoires et fichiers sensibles (admin, .git, .env) depuis l'IP 203.0.113.42 (web_access.log:8, web_access.log:12).
- C2 — 2024-11-15T21:18:15Z — observe : Tentatives d'injection SQL sur le paramètre 'q' de /search et sur /api/users/ (web_access.log:19, app.log:1).
- C3 — 2024-11-15T21:22:15Z — observe : Extraction réussie de données de la table 'users' via injection SQL (web_access.log:25, app.log:4).
- C4 — 2024-11-15T22:20:06Z — observe : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses (web_access.log:43, app.log:7).
- C5 — 2024-11-15T22:21:45Z — observe : Exfiltration de données massives (customers, backups) via l'interface admin (web_access.log:47, app.log:8).
- C6 — 2024-11-16T08:42:10Z — observe : Exécution d'un script PowerShell malveillant via Outlook sur PC-COMPTA-07 (edr_events.jsonl:2).
- C7 — 2024-11-16T08:42:13Z — tentative_bloquee : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy (edr_events.jsonl:6).
- C8 — date non vérifiée — present_dans_script : Capacité de bypass AMSI présente dans le script facture_2024-11.ps1 (facture_2024-11.ps1.txt:18).
- C9 — date non vérifiée — present_dans_script : Capacité de persistance via Tâches Planifiées et Registre présente dans le script (facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:80).
- C10 — date non vérifiée — present_dans_script : Capacité de keylogging et exfiltration de données système présente dans le script (facture_2024-11.ps1.txt:117, facture_2024-11.ps1.txt:144).

## IOC vérifiés

- ip `203.0.113.42` : IP source des scans de répertoires sensibles et des tentatives d'injection SQL ; confiance haute ; app.log:7, web_access.log:7, web_access.log:8, web_access.log:9, web_access.log:10, web_access.log:11, web_access.log:12, web_access.log:13, web_access.log:14, web_access.log:15, web_access.log:16, web_access.log:17, web_access.log:18, web_access.log:19, web_access.log:20, web_access.log:21, web_access.log:22, web_access.log:23, web_access.log:24, web_access.log:25, web_access.log:26, web_access.log:30, web_access.log:31, web_access.log:32, web_access.log:33, web_access.log:34, web_access.log:35, web_access.log:36, web_access.log:37, web_access.log:38, web_access.log:39, web_access.log:40, web_access.log:41, web_access.log:42, web_access.log:43, web_access.log:44, web_access.log:45, web_access.log:46, web_access.log:47, web_access.log:50, web_access.log:51 ; constats C1, C2
- ip `192.168.1.100` : Cible de connexion réseau bloquée par le proxy et présente dans le script malveillant ; confiance haute ; edr_events.jsonl:6, facture_2024-11.ps1.txt:22, facture_2024-11.ps1.txt:144 ; constats C7
- compte `admin` : Compte administrateur compromis utilisé pour l'exfiltration de données ; confiance haute ; app.log:5, app.log:7, ticket_INC-2026-0417.md:7, web_access.log:8, web_access.log:20, web_access.log:26, web_access.log:44, web_access.log:45, web_access.log:46, web_access.log:47, web_access.log:50, web_access.log:51, web_access.log:55, web_access.log:56, web_access.log:57 ; constats C4, C5
- fichier `facture_2024-11.ps1` : Script PowerShell malveillant avec capacités de bypass AMSI, persistance et keylogging ; confiance haute ; edr_events.jsonl:1, edr_events.jsonl:2, ticket_INC-2026-0417.md:12, ticket_INC-2026-0417.md:13 ; constats C6, C8, C9, C10

## MITRE ATT&CK

{"derniere_version":"20.1","fraicheur":"a_jour","sha256":"539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5","source":"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json","verifie_le":"2026-11-05T17:20:46.301083+00:00","version":"20.1"}
- T1595.002 — Vulnerability Scanning (reconnaissance) : Le scan de répertoires et fichiers sensibles (admin, .git, .env) correspond à la recherche de vulnérabilités et d'informations sur la configuration du système.
  - C1 : observe ; web_access.log:8, web_access.log:12
- T1190 — Exploit Public-Facing Application (initial-access) : L'utilisation d'injections SQL sur les paramètres de recherche et d'API pour extraire des données de la table 'users' est une exploitation de vulnérabilité d'une application exposée.
  - C2 : observe ; web_access.log:19, app.log:1
  - C3 : observe ; web_access.log:25, app.log:4
- T1110 — Brute Force (credential-access) : L'accès réussi au compte 'admin' après plusieurs tentatives infructueuses indique une attaque par force brute.
  - C4 : observe ; web_access.log:43, app.log:7
- T1020 — Automated Exfiltration (exfiltration) : L'exfiltration de données massives via l'interface admin et la capacité d'exfiltration de données système dans le script correspondent à l'exfiltration automatisée.
  - C5 : observe ; web_access.log:47, app.log:8
  - C10 : present_dans_script ; facture_2024-11.ps1.txt:117, facture_2024-11.ps1.txt:144
- T1059.001 — PowerShell (execution) : L'exécution d'un script PowerShell malveillant via Outlook est une utilisation de PowerShell pour l'exécution de code.
  - C6 : observe ; edr_events.jsonl:2
- T1685 — Disable or Modify Tools (defense-impairment) : La capacité de bypass AMSI présente dans le script est une technique pour désactiver ou modifier les outils de sécurité (remplace T1562.001).
  - C8 : present_dans_script ; facture_2024-11.ps1.txt:18
- T1053.005 — Scheduled Task (execution, persistence, privilege-escalation) : L'utilisation de Tâches Planifiées pour la persistance est explicitement décrite dans T1053.005.
  - C9 : present_dans_script ; facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:80
- T1112 — Modify Registry (defense-impairment, persistence) : L'utilisation du Registre pour la persistance correspond à la modification du registre Windows.
  - C9 : present_dans_script ; facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:80
- T1056.001 — Keylogging (collection, credential-access) : La capacité de keylogging est une technique de capture d'entrées clavier.
  - C10 : present_dans_script ; facture_2024-11.ps1.txt:117, facture_2024-11.ps1.txt:144

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
    "regle_sha256": "c8c4bcb07cf4fc57934efbe776257f1e7631655f20d52c5f2701da6c2ee42b3a",
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
    "regle_sha256": "7ce6d9ee8331f4cccbf1e16e20e5cbf4c96c376fc63babe1b05ee179c23b6653",
    "corpus_sha256": "80716d103cb47434d49e2899c9e19578b2907e1f24974b61991dc2c9ef615702",
    "vrais_positifs": [
      "facture_2024-11.ps1.txt"
    ],
    "faux_negatifs": [],
    "faux_positifs": [],
    "nb_scripts_legitimes_testes": 6,
    "tentative": 3
  }
}
```

## Confinement et décision humaine

```json
{
  "proposition": {
    "synthese": "L'incident présente un double vecteur d'attaque : une intrusion externe via le serveur web (IP 203.0.113.42) ayant mené à une exfiltration de données via le compte admin, et une compromission interne sur le poste PC-COMPTA-07 via un script PowerShell malveillant. La stratégie de confinement vise à couper les accès de l'attaquant externe, neutraliser le compte compromis et isoler la machine infectée pour stopper l'exfiltration et la persistance.",
    "actions": [
      {
        "id": "A1",
        "action": "Blocage de l'adresse IP 203.0.113.42 au niveau du pare-feu périmétrique.",
        "cible": "203.0.113.42",
        "constat_ids": [
          "C1",
          "C2"
        ],
        "preuves": [
          {
            "fichier": "web_access.log",
            "ligne": 8,
            "sha256": "cc15f170258dc57cc50ebddec9aa3911dfc93f69258c53c20ee47f9d00b18810"
          }
        ],
        "justification": "L'IP 203.0.113.42 est responsable de scans de fichiers sensibles et de tentatives d'injection SQL sur le serveur web.",
        "impact_attendu": "Blocage des tentatives de scan et d'injection SQL provenant de cette source.",
        "risques": "Faible, sauf si l'IP appartient à un service légitime non identifié."
      },
      {
        "id": "A2",
        "action": "Désactivation et réinitialisation du mot de passe du compte administrateur 'admin' sur le serveur web.",
        "cible": "admin",
        "constat_ids": [
          "C4",
          "C5"
        ],
        "preuves": [
          {
            "fichier": "web_access.log",
            "ligne": 43,
            "sha256": "cc15f170258dc57cc50ebddec9aa3911dfc93f69258c53c20ee47f9d00b18810"
          }
        ],
        "justification": "Le compte 'admin' a été compromis et utilisé pour exfiltrer des données massives (customers, backups).",
        "impact_attendu": "Interruption immédiate de l'accès non autorisé et arrêt de l'exfiltration de données via l'interface admin.",
        "risques": "Interruption temporaire de l'administration légitime du serveur."
      },
      {
        "id": "A3",
        "action": "Isolation réseau du poste de travail PC-COMPTA-07.",
        "cible": "facture_2024-11.ps1",
        "constat_ids": [
          "C6",
          "C8",
          "C9",
          "C10"
        ],
        "preuves": [
          {
            "fichier": "edr_events.jsonl",
            "ligne": 2,
            "sha256": "c42e6d8ecdc79c99f09052137faad313fd26f84766519de98ddff33a07fbb38e"
          }
        ],
        "justification": "Le poste PC-COMPTA-07 a exécuté un script PowerShell malveillant possédant des capacités de bypass AMSI, de persistance et de keylogging.",
        "impact_attendu": "Arrêt de l'exécution du script malveillant, blocage de la persistance et de l'exfiltration de données système.",
        "risques": "Interruption de l'activité métier de l'utilisateur du poste PC-COMPTA-07."
      }
    ]
  },
  "decision": {
    "decision": "acceptee",
    "proposition_sha256": "8e7087ea614485e9c4396e9bd5e0287991c5b74eaefbb8ec3773cbeb2113635c",
    "acteur": "analyste_console",
    "motif": "",
    "utc": "2026-11-05T17:24:01.150717+00:00",
    "execution": "jamais_executee_par_agent"
  }
}
```
Aucune action exécutée par l'agent.
Protocole manuel détaillé : [protocole_confinement.md](protocole_confinement.md).

## Tentatives d'injection dans les preuves

web_access.log:7

## Limites et points à confirmer

Les contrôles vérifient les sources et la cohérence des artefacts ; la pertinence des interprétations reste à relire par l'analyste.
- Le script PowerShell a été analysé en version désarmée, certaines capacités n'ont pas été observées en conditions réelles sur le poste.

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
    "invocations": 3
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
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  },
  "protocole": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  },
  "rapport": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 1
  }
}
```

Traçabilité : audit.jsonl, etat_phases.json, manifest_preuves.json, resultats_tests.json et validation_finale.json.
