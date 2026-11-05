# Chronologie de l'incident INC-2026-0417

## Alerte 1 - Serveur web web-01 (15/Nov/2024)

### Trafic entrant depuis 203.0.113.42

- **18:12:33+01** / HTTP GET racine - navigateur normal
- **18:45:33+01** /api/login - connexion depuis 203.0.113.42
- **22:14:58+01** / - visite racine
- **22:15:01+01** /admin - tentative d'accès (403)
- **22:15:02+01** /administrator - 404
- **22:15:02+01** /wp-admin - 404
- **22:15:03+01** /phpmyadmin - 404
- **22:15:03+01** /.git/config - 404
- **22:15:04+01** /.env - 404
- **22:15:04+01** /backup.sql - 404
- **22:15:05+01** /config.php - 404
- **22:15:05+01** /test - 404
- **22:15:06+01** /debug - 404
- **22:18:11+01** /search?q=test
- **22:18:15+01** /search?q='%20OR%20'1'='1 - **INJECTION SQL détectée**
- **22:18:18+01** /search?q=admin'-- - **INJECTION SQL détectée**
- **22:18:22+01** /search?q=';DROP%20TABLE%20users;-- - **INJECTION SQL détectée (erreur 500)**
- **22:18:25+01** /search?q=';SELECT%20*%20FROM%20information_schema.tables;-- - **INJECTION SQL détectée**
- **22:18:30+01** /search?q=';SELECT%20table_name%20FROM%20information_schema.tables;-- - **INJECTION SQL détectée**
- **22:22:01+01** /search?q=';SELECT%20column_name%20FROM%20information_schema.columns%20WHERE%20table_name='users';-- - **INJECTION SQL détectée**
- **22:22:15+01** /search?q=';SELECT%20username,password,email%20FROM%20users;-- - **INJECTION SQL détectée**
- **22:22:30+01** /search?q=';SELECT%20*%20FROM%20users%20WHERE%20username='admin';-- - **INJECTION SQL détectée**
- **22:25:11+01** /api/health - HealthChecker (normal)
- **22:30:00+01** /metrics - Prometheus (normal)
- **22:45:33+01** /api/contact - contact (normal)
- **23:10:05+01** /api/users/1 - consultation
- **23:10:08+01** /api/users/1' - **INJECTION SQL détectée (erreur 500)**
- **23:10:12+01** /api/users/1'%20AND%201=1-- - **INJECTION SQL détectée**
- **23:10:15+01** /api/users/1'%20AND%201=2-- - **INJECTION SQL détectée**
- **23:15:30+01** /admin/backup/download?file=db_dump_2024.sql.gz - **Téléchargement de fichier SQL** (4.5MB)
- **23:15:45+01** /admin/backup/download?file=customers_full.csv - **Téléchargement massif** (2.3MB)
- **23:21:01+01** /admin/dashboard - accès admin
- **23:21:15+01** /admin/users - accès admin
- **23:21:30+01** /admin/export?format=csv - export CSV
- **23:21:45+01** /admin/export?table=customers&format=sql - **Export SQL massif** (1.5MB)
- **02:00:11+01** (16/Nov) /admin/backup/download?file=db_dump_2024.sql.gz - nouveau téléchargement (4.5MB)
- **02:00:45+01** (16/Nov) /admin/backup/download?file=customers_full.csv - nouveau téléchargement (2.3MB)

### Événements applicatifs (app.log) - même plage horaire

- **21:18:22Z** - Erreur syntax SQL près de '' OR '1'='1' à ligne 1
- **21:18:25Z** - Erreur DROP TABLE non permis
- **21:18:30Z** - Pattern inhabituel : accès information_schema
- **21:22:15Z** - SELECT sur table sensible 'users' - colonnes: username,password,email
- **21:22:30Z** - Requête réussie pour user 'admin'
- **22:10:15Z** - Pattern boolean-based détecté (AND 1=1)
- **22:20:06Z** - Connexion réussie admin depuis 203.0.113.42
- **22:21:45Z** - Export de données massif initié - table: customers, format: sql
- **01:00:11Z** (16/Nov) - Téléchargement de fichier de sauvegarde - taille: 4.5MB
- **01:00:45Z** (16/Nov) - ALERT : Export massif de données - customers_full.csv (2.3MB)

## Alerte 2 - Poste PC-COMPTA-07 (16/Nov/2024)

- **08:41:52Z** - Création de fichier : C:\Users\m.durand\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\X7K2P9QZ\facture_2024-11.ps1 (via OUTLOOK.EXE)
- **08:42:10Z** - Création de processus : powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ...facture_2024-11.ps1 (depuis OUTLOOK.EXE, PID 6412)
- **08:42:11Z** - Requête WMI : SELECT * FROM AntivirusProduct (PID 6412)
- **08:42:11Z** - Requête WMI : SELECT * FROM Win32_BIOS (PID 6412)
- **08:42:12Z** - Requête DNS : malicious-domain.ru (PID 6412, résultat NXDOMAIN)
- **08:42:13Z** - Connexion réseau : PID 6412 vers 192.168.1.100:8080 (bloquée par proxy)
- **08:42:15Z** - Isolation hôte par l'astreinte

## Liens potentiels

- L'IP 203.0.113.42 a scanné et injecté SQL sur web-01 la nuit du 15/Nov
- Le même jour, le poste PC-COMPTA-07 a exécuté une pièce jointe malveillante
- Le script PowerShell télécharge depuis : http://192.168.1.100/stage1.ps1, http://192.168.1.101/beacon.exe, http://malicious-domain.ru/payload.dll
- La requête DNS vers malicious-domain.ru depuis le poste coïncide avec le domaine mentionné dans le script