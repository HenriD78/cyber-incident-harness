# Rapport d'incident INC-2026-0417

**Statut : INCOMPLET / NON VALIDÉ**

## Résumé exécutif

L'incident comprend deux attaques distinctes sans lien technique prouvé. Une compromission du serveur web a été réalisée via injection SQL (C2) après reconnaissance (C1), permettant l'usurpation du compte admin (C3) et l'exfiltration massive de données (C4). Parallèlement, le poste PC-COMPTA-07 a été infecté par un malware PowerShell via phishing (C5), présentant des capacités de persistance, de keylogging et de bypass AMSI (C7), avec des tentatives de C2 bloquées (C6).
Sources : web_access.log:8, web_access.log:10, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, web_access.log:51, app.log:10, edr_events.jsonl:2, edr_events.jsonl:6, facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117

## Qualification et lien entre alertes

- alerte_web : Compromission confirmée du serveur web via injection SQL, suivie d'une usurpation de compte admin et d'une exfiltration massive de données. (web_access.log:8, web_access.log:10, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, web_access.log:51, app.log:10).
- alerte_poste : Infection confirmée par malware PowerShell via phishing, avec tentatives de C2 bloquées et capacités de persistance/espionnage. (edr_events.jsonl:2, edr_events.jsonl:6, facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117).

Aucun lien prouvé : Aucun lien technique prouvé entre l'attaque web (IP 203.0.113.42) et l'infection du poste (C2 192.168.1.100). Les attaques sont distinctes temporellement et techniquement.
Sources du lien : non vérifié

## Chronologie et constats

- C1 — 2024-11-15T21:15:01Z — observe : Tentatives de reconnaissance et de scan de répertoires administratifs depuis l'IP 203.0.113.42 (web_access.log:8, web_access.log:10).
- C2 — 2024-11-15T21:22:15Z — observe : Injections SQL réussies permettant l'extraction de données de la table 'users' (username, password, email) (web_access.log:25, app.log:4).
- C3 — 2024-11-15T22:20:06Z — observe : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses (web_access.log:43, app.log:7).
- C4 — 2024-11-16T01:00:45Z — observe : Exfiltration de données massives (table customers et backups SQL) via le compte admin (web_access.log:47, web_access.log:51, app.log:10).
- C5 — 2024-11-16T08:42:10Z — observe : Exécution d'un script PowerShell malveillant via Outlook sur le poste PC-COMPTA-07 (edr_events.jsonl:2).
- C6 — 2024-11-16T08:42:13Z — tentative_bloquee : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy (edr_events.jsonl:6).
- C7 — date non vérifiée — present_dans_script : Capacités de bypass AMSI, persistance (Registry, Scheduled Tasks) et keylogging présentes dans le script (facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117).

## IOC vérifiés


## MITRE ATT&CK

{"derniere_version":"20.1","fraicheur":"a_jour","sha256":"539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5","source":"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json","verifie_le":"2026-11-05T16:39:55.833558+00:00","version":"20.1"}
- T1595.002 — Vulnerability Scanning (reconnaissance) : Tentatives de reconnaissance et de scan de répertoires administratifs pour identifier des vulnérabilités.
  - C1 : observe ; web_access.log:8, web_access.log:10
- T1190 — Exploit Public-Facing Application (initial-access) : Exploitation d'une vulnérabilité d'injection SQL sur une application publique pour extraire des données.
  - C2 : observe ; web_access.log:25, app.log:4
- T1110 — Brute Force (credential-access) : Accès réussi au compte admin après plusieurs tentatives infructueuses, caractéristique d'un brute force.
  - C3 : observe ; web_access.log:43, app.log:7
- T1020 — Automated Exfiltration (exfiltration) : Exfiltration massive de données (tables customers et backups) via un compte compromis.
  - C4 : observe ; web_access.log:47, web_access.log:51, app.log:10
- T1059.001 — PowerShell (execution) : Exécution d'un script PowerShell malveillant.
  - C5 : observe ; edr_events.jsonl:2
- T1685 — Disable or Modify Tools (defense-impairment) : Capacités de bypass AMSI présentes dans le script pour neutraliser les outils de défense.
  - C7 : present_dans_script ; facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117
- T1547.001 — Registry Run Keys / Startup Folder (persistence, privilege-escalation) : Capacités de persistance via Registry et Scheduled Tasks présentes dans le script.
  - C7 : present_dans_script ; facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117
- T1056.001 — Keylogging (collection, credential-access) : Capacités de keylogging présentes dans le script pour capturer des identifiants.
  - C7 : present_dans_script ; facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117

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
    "regle_sha256": "c5821b24bd2c5472d25abfdc228e3bbba9d558bf85113b157fa43d2698c0d153",
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
    "regle_sha256": "23dbbd042759ecc77043ad35729bdc688f353684ae393efb7c8ecd4277f17215",
    "corpus_sha256": "80716d103cb47434d49e2899c9e19578b2907e1f24974b61991dc2c9ef615702",
    "vrais_positifs": [
      "facture_2024-11.ps1.txt"
    ],
    "faux_negatifs": [],
    "faux_positifs": [],
    "nb_scripts_legitimes_testes": 6,
    "tentative": 2
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
- ioc : echec — save_iocs : 3 appels invalides ; dernier refus : Vérifier l'IOC et conserver toutes ses occurrences exactes
- confinement : bloquee — Prérequis ioc : phase echec
- Étape incomplète : iocs
- Étape incomplète : proposal
- Étape incomplète : decision
- L'analyse du script PowerShell est basée sur une version désarmée.

## État des phases

```json
{
  "preuves": {
    "statut": "terminee",
    "raisons": [],
    "invocations": 3
  },
  "ioc": {
    "statut": "echec",
    "raisons": [
      "save_iocs : 3 appels invalides ; dernier refus : Vérifier l'IOC et conserver toutes ses occurrences exactes"
    ],
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
    "statut": "bloquee",
    "raisons": [
      "Prérequis ioc : phase echec"
    ],
    "invocations": 0
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
