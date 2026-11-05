---
name: confinement
description: Préparer une piste consolidée et, après accord humain, son protocole manuel.
---
# Confinement exclusivement humain

## Phase confinement

1. Relire constats, IOC et résultats des tests. Soumettre UNE piste consolidée via
   `propose_containment(proposal)` : synthese et actions identifiées A1, A2…
2. Chaque action contient action, cible exacte vérifiée, constat_ids, preuves,
   justification, impact_attendu et risques. Justifier l'effet opérationnel et éviter
   les mesures disproportionnées. Un poste déjà isolé ne doit pas être présenté comme
   devant être isolé pour la première fois. Une hypothèse ne suffit pas à autoriser une action.
   `cible` contient uniquement la valeur exacte présente dans les IOC ou preuves :
   par exemple `admin`, pas `compte admin` ; `PC-COMPTA-07`, pas `poste PC-COMPTA-07`.
   Décrire le type de cible et le système concerné dans `action` et `justification`.
   Les objets de `preuves` doivent appartenir aux `constat_ids` de CETTE action,
   et non simplement apparaître quelque part dans l'incident. Les cibles IOC et
   références par constat sont fournies dans `contexte_confinement` par l'hôte.
   Après une erreur de validation renvoyée par l'outil, corriger toutes les erreurs des actions indiquées,
   avant de soumettre de nouveau la proposition. Aucun champ d'approbation n'est admis.
3. Terminer. L'hôte présente la proposition à l'équipe humaine en console.
   Ne jamais écrire une décision ou prétendre qu'une action a été exécutée.

## Phase protocole (uniquement après acceptation)

4. Relire proposition_confinement.json et containment.json via read_artifact.
5. Préparer `save_protocol(protocol)` : proposition_sha256 exacte et actions contenant
   action_id, cible identique, responsable, prerequis, etapes, verifications,
   criteres_arret et retour_arriere. Couvrir exactement les actions approuvées.
6. Détailler les manipulations manuelles. Toute information d'infrastructure inconnue
   est un prérequis à faire confirmer ; ne pas inventer un produit, identifiant ou accès.
   Ne pas étendre les cibles ou ajouter de nouvelles mesures dans le texte des étapes.
7. Aucune commande n'est exécutée par l'agent. En cas de refus, cette phase est sautée :
   aucune nouvelle piste, aucun protocole, uniquement le rapport puis l'arrêt.
