---
name: extraction-ioc
description: Extraire et enregistrer les IOC vérifiés avec provenance et contexte.
---
# IOC vérifiés

1. Relire `analyse.json` via `read_artifact` et les preuves utiles via `read_evidence`.
2. Dédupliquer par valeur. Appeler `verify_ioc(value)` une seule fois par valeur distincte.
   Conserver TOUTES les références exactes renvoyées. Une présence n'est pas une preuve
   de malveillance : expliquer le rôle de l'indicateur et rattacher aux constats Cn.
3. Pour une chaîne encodée, utiliser `decode_evidence(fichier, ligne, encoded)` avec
   la chaîne exacte présente à cette ligne. Ne jamais exécuter le texte décodé.
   Un IOC dérivé cite uniquement la source encodée et le `derivation_id` fourni.
   Il n'est pas nécessaire que sa valeur décodée apparaisse en clair dans les preuves.
4. Appeler `save_iocs(iocs)` : chaque objet contient type (`ip`, `domaine`, `url`, `hash`,
   `chemin`, `compte`, `fichier`, `autre`), valeur, references, contexte,
   confiance (`haute`, `moyenne`, `faible`), constat_ids, derivation_id (ou null).
5. Distinguer IOC internes, outils légitimes et indicateurs réellement associés à l'attaque.
   Ne pas retenir une valeur introuvable ou une dérivation sans provenance.
6. Si `save_iocs` est refusé, corriger TOUS les IOC indiqués par `valeur` et `champ` :
   ajouter les objets exacts de `references_manquantes`, retirer ceux de
   `references_inattendues` (ou les doublons), et effectuer les `appel_requis`.
   Les références incluent aussi les occurrences présentes dans du code commenté ;
   leur présence ne signifie pas que ce code a été exécuté. Ne pas réduire la liste
   aux seules lignes jugées malveillantes et ne pas répéter un lot inchangé en erreur.
