# Protocole manuel de confinement

Aucune action exécutée par l'agent. Vérifier les prérequis avant application.
Proposition approuvée : `8e7087ea614485e9c4396e9bd5e0287991c5b74eaefbb8ec3773cbeb2113635c`

## A1 — Blocage de l'adresse IP 203.0.113.42 au niveau du pare-feu périmétrique.
Cible : 203.0.113.42. Responsable : Équipe Réseau/Sécurité.

### prerequis

1. Accès administrateur au pare-feu périmétrique.

### etapes

1. Accéder à l'interface d'administration du pare-feu périmétrique.
2. Créer une règle de blocage (Deny) pour tout trafic entrant provenant de l'adresse IP 203.0.113.42.
3. Appliquer la configuration et vérifier que la règle est active.

### verifications

1. Tenter une connexion depuis une source externe simulée (si possible) ou vérifier les logs du pare-feu pour confirmer le rejet des paquets de l'IP 203.0.113.42.

### criteres_arret

1. Confirmation du blocage effectif de l'IP sur le pare-feu périmétrique.

### retour_arriere

1. Supprimer la règle de blocage de l'IP 203.0.113.42.
## A2 — Désactivation et réinitialisation du mot de passe du compte administrateur 'admin' sur le serveur web.
Cible : admin. Responsable : Équipe Administration Système.

### prerequis

1. Accès administrateur au serveur web.

### etapes

1. Se connecter au serveur web avec un compte administrateur légitime.
2. Accéder à la gestion des utilisateurs.
3. Désactiver le compte 'admin'.
4. Réinitialiser le mot de passe du compte 'admin' avec une valeur forte et aléatoire.

### verifications

1. Tenter de se connecter avec les anciens identifiants du compte 'admin' pour confirmer l'échec de l'accès.

### criteres_arret

1. Confirmation de la désactivation du compte et du changement de mot de passe.

### retour_arriere

1. Réactiver le compte 'admin' et restaurer l'ancien mot de passe (si connu et sécurisé).
## A3 — Isolation réseau du poste de travail PC-COMPTA-07.
Cible : facture_2024-11.ps1. Responsable : Équipe Sécurité/IT Support.

### prerequis

1. Accès administrateur à la console EDR ou au commutateur réseau.

### etapes

1. Accéder à la console de gestion de l'EDR ou du commutateur réseau.
2. Identifier le poste PC-COMPTA-07.
3. Activer l'isolation réseau du poste (Network Isolation) pour bloquer tout trafic entrant et sortant, sauf vers la console de gestion.

### verifications

1. Vérifier dans la console EDR que le statut du poste est 'Isolé'. Tenter un ping depuis un autre poste du réseau vers PC-COMPTA-07 pour confirmer l'absence de réponse.

### criteres_arret

1. Confirmation de l'isolation réseau du poste PC-COMPTA-07.

### retour_arriere

1. Désactiver l'isolation réseau du poste PC-COMPTA-07.