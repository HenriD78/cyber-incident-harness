# Chronologie UTC

| UTC | Constat | Statut | Preuves |
|---|---|---|---|
| 2024-11-15T21:15:01Z | C1 : Scan de répertoires et fichiers sensibles (admin, .git, .env) depuis l'IP 203.0.113.42 | observe | web_access.log:8, web_access.log:12 |
| 2024-11-15T21:18:15Z | C2 : Tentatives d'injection SQL sur le paramètre 'q' de /search et sur /api/users/ | observe | web_access.log:19, app.log:1 |
| 2024-11-15T21:22:15Z | C3 : Extraction réussie de données de la table 'users' via injection SQL | observe | web_access.log:25, app.log:4 |
| 2024-11-15T22:20:06Z | C4 : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses | observe | web_access.log:43, app.log:7 |
| 2024-11-15T22:21:45Z | C5 : Exfiltration de données massives (customers, backups) via l'interface admin | observe | web_access.log:47, app.log:8 |
| 2024-11-16T08:42:10Z | C6 : Exécution d'un script PowerShell malveillant via Outlook sur PC-COMPTA-07 | observe | edr_events.jsonl:2 |
| 2024-11-16T08:42:13Z | C7 : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy | tentative_bloquee | edr_events.jsonl:6 |
| non vérifié | C8 : Capacité de bypass AMSI présente dans le script facture_2024-11.ps1 | present_dans_script | facture_2024-11.ps1.txt:18 |
| non vérifié | C9 : Capacité de persistance via Tâches Planifiées et Registre présente dans le script | present_dans_script | facture_2024-11.ps1.txt:64, facture_2024-11.ps1.txt:80 |
| non vérifié | C10 : Capacité de keylogging et exfiltration de données système présente dans le script | present_dans_script | facture_2024-11.ps1.txt:117, facture_2024-11.ps1.txt:144 |