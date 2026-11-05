# Rapport d'incident INC-2026-0417

**Statut : INCOMPLET / NON VALIDÉ**

## Résumé exécutif

L'incident combine deux attaques distinctes sans lien technique prouvé. Le serveur web-01 a été compromis via une injection SQL et un vol de credentials, menant à l'exfiltration massive de données clients. Parallèlement, le poste PC-COMPTA-07 a été infecté par un malware PowerShell via phishing, avec des capacités de persistance et de keylogging, bien que la communication C2 ait été bloquée.
Sources : web_access.log:8, web_access.log:12, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, app.log:8, web_access.log:50, edr_events.jsonl:2, edr_events.jsonl:6, facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117

## Qualification et lien entre alertes

- alerte_web : Compromission confirmée du serveur web-01 via injection SQL et vol de credentials, aboutissant à l'exfiltration de données clients. (web_access.log:8, web_access.log:12, web_access.log:25, app.log:4, web_access.log:43, app.log:7, web_access.log:47, app.log:8, web_access.log:50).
- alerte_poste : Infection confirmée du poste PC-COMPTA-07 par un malware PowerShell via phishing, tentative de communication C2 bloquée. (edr_events.jsonl:2, edr_events.jsonl:6, facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117).

Aucun lien prouvé : Aucun lien technique direct (IP, compte, fichier) n'est prouvé entre l'attaque sur le serveur web (203.0.113.42) et l'infection du poste (m.durand).
Sources du lien : non vérifié

## Chronologie et constats

- C1 — 2024-11-15T21:15:01Z — observe : Tentatives de scan de répertoires administratifs et fichiers de configuration par l'IP 203.0.113.42 (web_access.log:8, web_access.log:12).
- C2 — 2024-11-15T21:22:15Z — observe : Injections SQL réussies sur le paramètre 'q' de /search permettant l'extraction de données de la table 'users' (web_access.log:25, app.log:4).
- C3 — 2024-11-15T22:20:06Z — observe : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses (brute force ou utilisation de credentials volés) (web_access.log:43, app.log:7).
- C4 — 2024-11-15T22:21:45Z — observe : Exfiltration de données massives (table customers et backup SQL) via le compte admin (web_access.log:47, app.log:8, web_access.log:50).
- C5 — 2024-11-16T08:42:10Z — observe : Exécution d'un script PowerShell malveillant (facture_2024-11.ps1) lancé depuis Outlook (edr_events.jsonl:2).
- C6 — 2024-11-16T08:42:13Z — tentative_bloquee : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy (edr_events.jsonl:6).
- C7 — date non vérifiée — present_dans_script : Capacités de bypass AMSI, persistance via registre/tâches planifiées et keylogging présentes dans le script (facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117).

## IOC vérifiés


## MITRE ATT&CK

{"derniere_version":"20.0","fraicheur":"a_jour","sha256":"81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352","source":"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json","verifie_le":"2026-11-05T15:48:43.244156+00:00","version":"20.0"}
- T1046 — Network Service Discovery (discovery) : Tentatives de scan de répertoires administratifs et fichiers de configuration pour identifier des services ou informations sensibles.
  - C1 : observe ; web_access.log:8, web_access.log:12
- T1213.006 — Databases (collection) : Utilisation d'injections SQL pour extraire des données de la table 'users' d'une base de données.
  - C2 : observe ; web_access.log:25, app.log:4
- T1110 — Brute Force (credential-access) : Accès réussi au compte admin après plusieurs tentatives infructueuses, caractéristique d'un brute force.
  - C3 : observe ; web_access.log:43, app.log:7
- T1020 — Automated Exfiltration (exfiltration) : Exfiltration massive de données (table customers et backup SQL) via un compte compromis.
  - C4 : observe ; web_access.log:47, app.log:8, web_access.log:50
- T1059.001 — PowerShell (execution) : Exécution d'un script PowerShell malveillant lancé depuis Outlook.
  - C5 : observe ; edr_events.jsonl:2
- T1027 — Obfuscated Files or Information (stealth) : Présence de capacités de bypass AMSI dans le script pour échapper à la détection.
  - C7 : present_dans_script ; facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117
- T1547.001 — Registry Run Keys / Startup Folder (persistence, privilege-escalation) : Capacités de persistance via le registre présentes dans le script.
  - C7 : present_dans_script ; facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117
- T1053.005 — Scheduled Task (execution, persistence, privilege-escalation) : Capacités de persistance via des tâches planifiées présentes dans le script.
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
    "regle_sha256": "9f2a38d54fa7db1861f4d99cf37d8994db38db6377e360af2bdf84edd53b6cb5",
    "titre": "PowerShell launched by Outlook with Bypass and Hidden",
    "logsource": "SigmaLogSource(category='process_creation', product='windows', service=None, definition=None, source=None, custom_attributes=None)",
    "corpus_sha256": "cb09edd06642a8324f9b4b404c78c26420a60f8f56742c9fc69afb5d46f948e5",
    "faux_positifs": [],
    "faux_negatifs": [],
    "nb_negatifs": 4,
    "tentative": 3
  },
  "yara": {
    "compile": false,
    "test_concluant": false,
    "verdict": "À REVOIR",
    "regle_sha256": "c764cebdf80b697a9fbf62cefa8deb151fa1cfb0a94fcadddabb2f35efc031f4",
    "corpus_sha256": "80716d103cb47434d49e2899c9e19578b2907e1f24974b61991dc2c9ef615702",
    "erreur": "line 18: unreferenced string \"$task_trigger\"",
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
- ioc : echec — save_iocs : 3 appels invalides ; dernier refus : Vérifier l'IOC et conserver toutes ses occurrences exactes
- regles : echec — Test yara non réussi (4/4 essais)
- confinement : bloquee — Prérequis ioc : phase echec
- Étape incomplète : iocs
- Étape incomplète : proposal
- Étape incomplète : decision
- Test yara non réussi
- L'analyse du script PowerShell est basée sur une version désarmée.
- La règle YARA n'a pas pu être validée suite à une erreur de compilation.

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
    "statut": "echec",
    "raisons": [
      "Test yara non réussi (4/4 essais)"
    ],
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
