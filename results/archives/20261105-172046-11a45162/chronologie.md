# Chronologie UTC

| UTC | Constat | Statut | Preuves |
|---|---|---|---|
| 2024-11-15T21:15:01Z | C1 : Scan de répertoires administratifs et fichiers sensibles depuis l'IP 203.0.113.42 | observe | web_access.log:8, web_access.log:12 |
| 2024-11-15T21:18:30Z | C2 : Tentatives d'injection SQL réussies sur le paramètre 'q' de /search, permettant l'énumération de la table 'users' | observe | web_access.log:23, app.log:3 |
| 2024-11-15T21:22:15Z | C3 : Extraction de données sensibles (table users) via injection SQL | observe | web_access.log:25, app.log:4 |
| 2024-11-15T22:20:06Z | C4 : Accès réussi au compte 'admin' après plusieurs tentatives infructueuses (Brute force/Credential Stuffing) | observe | web_access.log:43, app.log:7 |
| 2024-11-15T22:21:45Z | C5 : Exfiltration de données massives via l'interface admin (exports SQL et CSV) | observe | web_access.log:47, app.log:8 |
| 2024-11-16T01:00:11Z | C6 : Téléchargement de dumps de base de données et fichiers clients | observe | web_access.log:50, app.log:9 |
| 2024-11-16T08:42:10Z | C7 : Exécution d'un script PowerShell malveillant via Outlook sur PC-COMPTA-07 | observe | edr_events.jsonl:2 |
| 2024-11-16T08:42:11Z | C8 : Collecte d'informations système (Antivirus, BIOS) via WMI | observe | edr_events.jsonl:3, edr_events.jsonl:4 |
| 2024-11-16T08:42:12Z | C9 : Tentative de résolution DNS vers un domaine malveillant (malicious-domain.ru) - NXDOMAIN | tentative_bloquee | edr_events.jsonl:5 |
| 2024-11-16T08:42:13Z | C10 : Tentative de connexion réseau vers 192.168.1.100:8080 bloquée par le proxy | tentative_bloquee | edr_events.jsonl:6 |
| non vérifié | C11 : Capacité de contournement AMSI présente dans le script | present_dans_script | facture_2024-11.ps1.txt:17 |
| non vérifié | C12 : Capacité de persistance via Tâches Planifiées et Registre présente dans le script | present_dans_script | facture_2024-11.ps1.txt:54, facture_2024-11.ps1.txt:72 |
| non vérifié | C13 : Capacité de keylogging via API user32.dll présente dans le script | present_dans_script | facture_2024-11.ps1.txt:117 |