# Chronologie de l'incident INC-2026-0417 (heure UTC)

## Alerte 1 - Serveur web web-01 (15/11/2024)

| Horodatage UTC | Source | Événement |
|---|---|---|
| 2024-11-15T21:14:58Z | web_access.log | Requête GET racine depuis 203.0.113.42 |
| 2024-11-15T21:15:01Z | web_access.log | Requête GET /admin depuis 203.0.113.42 (403) |
| 2024-11-15T21:18:11Z | web_access.log | Requête GET / depuis 203.0.113.42 |
| 2024-11-15T21:18:15Z | web_access.log | Requête GET /search?q='%20OR%20'1'='1 depuis 203.0.113.42 (injection SQL) |
| 2024-11-15T21:18:18Z | web_access.log | Requête GET /search?q='admin'-- depuis 203.0.113.42 |
| 2024-11-15T21:18:22Z | web_access.log | Requête GET /search?q=test depuis 203.0.113.42 |
| 2024-11-15T21:18:25Z | web_access.log | Requête GET /search?q=';DROP TABLE users;-- depuis 203.0.113.42 (erreur 500) |
| 2024-11-15T21:18:30Z | web_access.log | Requête GET /search?q=';SELECT*FROM information_schema.tables;-- depuis 203.0.113.42 |
| 2024-11-15T21:22:15Z | app.log | Erreur SQL syntax near '' OR '1'='1' |
| 2024-11-15T21:22:30Z | app.log | Alerte DROP TABLE non permis |
| 2024-11-15T21:22:30Z | app.log | Alerte accès information_schema |
| 2024-11-15T22:10:12Z | web_access.log | Requête GET /api/users' depuis 203.0.113.42 (erreur 500) |
| 2024-11-15T22:10:15Z | web_access.log | Requête GET /api/users/1' depuis 203.0.113.42 (erreur 500) |
| 2024-11-15T22:10:15Z | web_access.log | Requête GET /api/users/1' AND 1=1-- depuis 203.0.113.42 (vrai) |
| 2024-11-15T22:10:15Z | web_access.log | Requête GET /api/users/1' AND 1=2-- depuis 203.0.113.42 (faux) |
| 2024-11-15T22:15:22Z | app.log | Détection injection booléenne AND 1=1 |
| 2024-11-15T22:15:25Z | web_access.log | Gros téléchargement /admin/export?format=csv (2.3MB) |
| 2024-11-15T22:15:30Z | web_access.log | POST /api/upload (403) |
| 2024-11-15T22:15:35Z | web_access.log | PUT /files/shell.php (405) |
| 2024-11-15T22:15:40Z | web_access.log | POST /files/ (403) |
| 2024-11-15T22:20:01Z | web_access.log | 6 échecs de connexion POST /api/login depuis 203.0.113.42 |
| 2024-11-15T22:20:02Z | web_access.log | Échec connexion |
| 2024-11-15T22:20:03Z | web_access.log | Échec connexion |
| 2024-11-15T22:20:04Z | web_access.log | Échec connexion |
| 2024-11-15T22:20:05Z | web_access.log | Échec connexion |
| 2024-11-15T22:20:06Z | app.log | Alerte connexion réussie admin depuis 203.0.113.42 |
| 2024-11-15T22:21:01Z | web_access.log | GET /admin/dashboard depuis 203.0.113.42 (admin) |
| 2024-11-15T22:21:15Z | web_access.log | GET /admin/users depuis 203.0.113.42 (admin) |
| 2024-11-15T22:21:30Z | web_access.log | GET /admin/export?format=csv depuis 203.0.113.42 (admin) |
| 2024-11-15T22:21:45Z | web_access.log | GET /admin/export?table=customers&format=sql depuis 203.0.113.42 (admin) - 1.5MB |
| 2024-11-15T22:25:00Z | web_access.log | Requête saine GET /api/health depuis 192.168.1.55 (HealthChecker) |
| 2024-11-15T22:30:22Z | web_access.log | Requête saine GET /api/status depuis 192.168.1.200 (StatusChecker) |
| 2024-11-15T23:10:05Z | web_access.log | GET /api/users/1 (saine) depuis 203.0.113.42 |
| 2024-11-15T23:10:08Z | web_access.log | GET /api/users/1' (erreur 500) depuis 203.0.113.42 |
| 2024-11-15T23:10:12Z | web_access.log | GET /api/users/1' AND 1=1-- (vrai) depuis 203.0.113.42 |
| 2024-11-15T23:10:15Z | web_access.log | GET /api/users/1' AND 1=2-- (faux) depuis 203.0.113.42 |
| 2024-11-15T23:15:22Z | web_access.log | POST /upload (403) |
| 2024-11-15T23:15:25Z | web_access.log | POST /api/upload (403) |
| 2024-11-15T23:15:30Z | web_access.log | PUT /files/shell.php (405) |
| 2024-11-15T23:15:35Z | web_access.log | POST /files/ (403) |
| 2024-11-15T23:20:01Z | web_access.log | 6 échecs POST /api/login depuis 203.0.113.42 |
| 2024-11-15T23:20:02Z | web_access.log | Échec connexion |
| 2024-11-15T23:20:03Z | web_access.log | Échec connexion |
| 2024-11-15T23:20:04Z | web_access.log | Échec connexion |
| 2024-11-15T23:20:05Z | web_access.log | Échec connexion |
| 2024-11-15T23:20:06Z | app.log | Alerte connexion réussie admin depuis 203.0.113.42 |
| 2024-11-15T23:21:01Z | web_access.log | GET /admin/dashboard depuis 203.0.113.42 (admin) |
| 2024-11-15T23:21:15Z | web_access.log | GET /admin/users depuis 203.0.113.42 (admin) |
| 2024-11-15T23:21:30Z | web_access.log | GET /admin/export?format=csv depuis 203.0.113.42 (admin) |
| 2024-11-15T23:21:45Z | web_access.log | GET /admin/export?table=customers&format=sql depuis 203.0.113.42 (admin) - 1.5MB |
| 2024-11-15T23:25:00Z | web_access.log | Requête saine GET /robots.txt depuis 10.0.0.5 (Googlebot) |
| 2024-11-15T23:30:22Z | web_access.log | Requête saine GET /api/status depuis 192.168.1.200 |
| 2024-11-16T01:00:11Z | app.log | Alerte téléchargement backup - taille 4.5MB |
| 2024-11-16T01:00:45Z | web_access.log | GET /admin/backup/download?file=db_dump_2024.sql.gz depuis 203.0.113.42 (admin) - 4.5MB |
| 2024-11-16T01:00:45Z | web_access.log | GET /admin/backup/download?file=customers_full.csv depuis 203.0.113.42 (admin) - 2.3MB |
| 2024-11-16T07:00:12Z | web_access.log | Requête saine GET / depuis 192.168.1.45 (post-reboot) |
| 2024-11-16T07:15:33Z | web_access.log | POST /api/login depuis 192.168.1.78 (iPhone) |
| 2024-11-16T08:15:22Z | web_access.log | GET /dashboard depuis 192.168.1.102 (Mac) |
| 2024-11-16T08:15:45Z | web_access.log | GET /admin/dashboard depuis 192.168.1.150 (Windows) |
| 2024-11-16T08:16:00Z | web_access.log | GET /admin/logs depuis 192.168.1.150 (Windows) |

## Alerte 2 - Poste PC-COMPTA-07 (16/11/2024)

| Horodatage UTC | Source | Événement |
|---|---|---|
| 2024-11-16T08:41:52Z | edr_events.jsonl | Création de fichier : téléchargement de facture_2024-11.ps1 depuis Outlook vers cache |
| 2024-11-16T08:42:10Z | edr_events.jsonl | Création de processus : powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ...facture_2024-11.ps1 (depuis OUTLOOK.EXE) |
| 2024-11-16T08:42:11Z | edr_events.jsonl | Requête WMI : AntivirusProduct (détection d'antivirus) |
| 2024-11-16T08:42:11Z | edr_events.jsonl | Requête WMI : Win32_BIOS |
| 2024-11-16T08:42:12Z | edr_events.jsonl | Requête DNS : malicious-domain.ru (NXDOMAIN - non trouvé) |
| 2024-11-16T08:42:12Z | edr_events.jsonl | Connexion réseau vers 192.168.1.100:8080 (bloquée par le proxy) |
| 2024-11-16T08:42:15Z | edr_events.jsonl | Isolement du poste par l'astreinte |

**Remarque :** Le script PowerShell facture_2024-11.ps1 contient une charge utile encodée en Base64 qui décode en une commande Invoke-Expression, télécharge des stages depuis des URLs incluant http://192.168.1.100/stage1.ps1, http://192.168.1.101/beacon.exe, http://malicious-domain.ru/payload.dll, et crée une tâche planifiée pour la persistance.