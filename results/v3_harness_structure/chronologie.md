# Chronologie UTC

| UTC | Constat | Statut | Preuves |
|---|---|---|---|
| 2024-11-15T21:15:01Z | C1 : Tentatives de scan de répertoires administratifs et fichiers de configuration par l'IP 203.0.113.42 | observe | web_access.log:8, web_access.log:12 |
| 2024-11-15T21:22:15Z | C2 : Injections SQL réussies sur le paramètre 'q' de /search permettant l'extraction de données de la table 'users' | observe | web_access.log:25, app.log:4 |
| 2024-11-15T22:20:06Z | C3 : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses (brute force ou utilisation de credentials volés) | observe | web_access.log:43, app.log:7 |
| 2024-11-15T22:21:45Z | C4 : Exfiltration de données massives (table customers et backup SQL) via le compte admin | observe | web_access.log:47, app.log:8, web_access.log:50 |
| 2024-11-16T08:42:10Z | C5 : Exécution d'un script PowerShell malveillant (facture_2024-11.ps1) lancé depuis Outlook | observe | edr_events.jsonl:2 |
| 2024-11-16T08:42:13Z | C6 : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy | tentative_bloquee | edr_events.jsonl:6 |
| non vérifié | C7 : Capacités de bypass AMSI, persistance via registre/tâches planifiées et keylogging présentes dans le script | present_dans_script | facture_2024-11.ps1.txt:19, facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:117 |