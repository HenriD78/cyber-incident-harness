# Ticket INC-2026-0417 : escalade N1 → N2

**Ouvert par :** analyste N1 (astreinte)  **Priorité :** haute  **Statut :** à qualifier

## Alerte 1 : serveur web de production `web-01`
Le SIEM a levé plusieurs alertes de faible priorité dans la nuit (injections SQL, échecs de connexion,
gros téléchargements depuis `/admin`). Logs joints : `web_access.log` (Apache, heure locale +0100)
et `app.log` (journal applicatif, horodatage UTC).

## Alerte 2 : poste `PC-COMPTA-07`
Le lendemain matin, l'EDR a détecté l'exécution d'un script PowerShell ouvert depuis une pièce jointe
de courriel (`facture_2024-11.ps1`). Le poste a été isolé du réseau par l'astreinte. Événements EDR
joints : `edr_events.jsonl`. Copie du script (charge utile désarmée) : `facture_2024-11.ps1`.

## Demande
1. Qualifier les deux alertes et dire si elles sont liées (preuves à l'appui).
2. Lister les IOC **vérifiés**, mapper les techniques MITRE ATT&CK.
3. Proposer une règle Sigma et une règle YARA testées.
4. Proposer des actions de confinement (aucune action sans validation humaine).
5. Rédiger le rapport d'incident.
